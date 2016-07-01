#include "host.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int GetLocalhostInformation(char *name, struct in_addr *addr, struct in_addr *mask){
    char Buffer[256];
    struct hostent *LocalHostEntry;
    struct ifaddrs *CurrentIFAddr, *FirstIFAddr;
    int Found = 0;
    
    if(-1 == gethostname(Buffer, 255)){
        return -1;
    }
    LocalHostEntry = gethostbyname(Buffer);
    if(NULL == LocalHostEntry){
        return -1;
    }
    strcpy(name, LocalHostEntry->h_name);
    LocalHostEntry = gethostbyname(name);
    if(NULL == LocalHostEntry){
        return -1;
    }
    bcopy((char *)LocalHostEntry->h_addr, (char *)addr, LocalHostEntry->h_length);
    
    if(0 > getifaddrs(&FirstIFAddr)){
        return -1;
    }
    CurrentIFAddr = FirstIFAddr;
    do{
        if(AF_INET == CurrentIFAddr->ifa_addr->sa_family){
            if(0 == memcmp(&((struct sockaddr_in *)CurrentIFAddr->ifa_addr)->sin_addr, addr, LocalHostEntry->h_length)){
                bcopy((char *)&((struct sockaddr_in *)CurrentIFAddr->ifa_netmask)->sin_addr, (char *)mask, LocalHostEntry->h_length);
                Found = 1;
                break;
            }
        }
        CurrentIFAddr = CurrentIFAddr->ifa_next;
    }while(NULL != CurrentIFAddr);
    freeifaddrs(FirstIFAddr);
    if(!Found){
        return -1;
    }
    return 0;
}

Host::Host(){
	tcpFD = -1;
	state = TCP_NOT_CONNECTED;
	authenticated = false;
	auth_recvd = false;
	encrypted = false;
	secretNum = 0;
}

Host::Host(char* Buffer){
	hostname = (char*)malloc(strlen(Buffer+10) + 1);
	strcpy(hostname, Buffer+10);

	username = (char*)malloc(strlen(Buffer+10+strlen(hostname)+1));
	strcpy(username, (Buffer+10 + strlen(hostname) + 1));

	udpPort = ntohs(*(short*)(Buffer+6));
	tcpPort = ntohs(*(short*)(Buffer+8));

	tcpFD = -1;
	state = TCP_NOT_CONNECTED;
	authenticated = false;
	auth_recvd = false;
	encrypted = false;
	secretNum = 0;
}

Host::~Host(){
	free(hostname);
	free(username);
}

Host::Host(const Host &obj){
	hostname = (char*)malloc(strlen(obj.hostname) + 1);
	strcpy(hostname, obj.hostname);

	username = (char*)malloc(strlen(obj.username) + 1);
	strcpy(username, obj.username);

	udpPort = obj.udpPort;
	tcpPort = obj.tcpPort;
	tcpFD = obj.tcpFD;
	state = obj.state;
}

bool Host::operator==(const Host& b){
	//std::cout << "INSIDE operator ==" << std::endl;
	//std::cout << "hostname: " << !strcmp(this->hostname, b.hostname) << std::endl;
	//std::cout << "username: " << !strcmp(this->username, b.username) << std::endl;
	//std::cout << ((this->udpPort == b.udpPort) && (this->tcpPort == b.tcpPort) && !strcmp(this->hostname, b.hostname) && !strcmp(this->username, b.username)) << std::endl;
	return((this->udpPort == b.udpPort) && (this->tcpPort == b.tcpPort) && !strcmp(this->hostname, b.hostname) && !strcmp(this->username, b.username));
}

int Host::TCPConnectToHost(){
	if(this->tcpFD != -1){
		return -2;
	}

	struct sockaddr_in ServerAddress;
	struct hostent *Server;

	//Create socket
	this->tcpFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(0 > this->tcpFD){
        fprintf(stderr, "ERROR opening socket");
    }

    // Convert/resolve host name 
	Server = gethostbyname(this->hostname);
	if(NULL == Server){
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}

    //setup server address
	bzero((char *) &ServerAddress, sizeof(ServerAddress));
	ServerAddress.sin_family = AF_INET;
	bcopy((char *)Server->h_addr, (char *)&ServerAddress.sin_addr.s_addr, Server->h_length);
	ServerAddress.sin_port = htons(this->tcpPort);
    
    // Connect to server
	if(0 > connect(this->tcpFD, (struct sockaddr *)&ServerAddress, sizeof(ServerAddress))){
		fprintf(stderr, "ERROR connecting\n");
		close(this->tcpFD);
		this->tcpFD = -1;
	}

	this->state = TCP_PENDING;

	return this->tcpFD;
}

void Host::sendDataChunkHeader(char* header, int len){
	if(receiver){
        send_sequence++;
    } else { send_sequence--; }

    sendPacketToHost(header, len);
}

void Host::recvDataChunkHeader(){
	char tempBuffer[6];

	if(receiver){ 
		recv_sequence--;
	} else{ recv_sequence++; }

	read(tcpFD, tempBuffer, 6);
}

void Host::sendPacketToHost(char* packet, int packetLen){
	if(tcpFD != -1){
		int result = write(tcpFD, packet, packetLen);

		if(result < 0){
			std::cerr << "Error on writing to Host " << username << "@" << hostname << std::endl;
		}
	}
	else{
		std::cerr << "Invalid socket" << std::endl;
	}
}

bool Host::closeConnection(int* tcpConnections, int pollfd_index, struct pollfd* fds, std::map<int, Host*>* tcpHosts){
	if(this->state == TCP_NOT_CONNECTED) {
		return false;
	}

	close(this->tcpFD);

	for(int i = pollfd_index + 1; i < *tcpConnections; i++){
		fds[3+i-1].fd = fds[3+i].fd;
		fds[3+i-1].events = fds[3+i].events; 
	}

	(*tcpConnections)--;

	//remove from map
    tcpHosts->erase(this->tcpFD);

    //update this host
    this->state = TCP_NOT_CONNECTED;
    this->tcpFD = -1;

    encrypted = false;

    return true;
}

int Host::checkAuthentication(){
	if(!auth_recvd){
		return WAITING_FOR_ANCHOR;
	}
	if(pub_key == trust_pub_key && mod == trust_mod){
		//printf("%s authenticated.\n", myHosts[i]->username);
		authenticated = true;
		return AUTH;
	} else if(trust_pub_key == 0 && trust_mod == 0){
		return NOT_IN_ANCHOR;
	}

	return UNAUTH;
}

void Host::printHost(int index){
	printf("User %i %s@%s UDP %i TCP %i ", index, this->username, this->hostname, this->udpPort, this->tcpPort);

	if(checkAuthentication() == AUTH){
		printf("Verified\n");
	} else { printf("Not Verified\n"); }
}

void Host::debug(){
	std::cout << "*************************************************" << std::endl;
	std::cout << "Hostname: " << hostname << std::endl;
	std::cout << "Username: " << username << std::endl;
	std::cout << "UDP Port: " << udpPort << std::endl;
	std::cout << "TCP Port: " << tcpPort << std::endl;
	std::cout << "*************************************************" << std::endl;
}