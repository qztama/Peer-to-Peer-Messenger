#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <signal.h>
#include <poll.h>
#include <termios.h>
#include <ctype.h>
#include <errno.h>

#include "EncryptionLibrary.h"
#include <iostream>
#include <vector>
#include <map>
#include "host.h"
#include "packets.h"

#define MAX_TCP_CONNECTIONS     10
#define DEFAULT_FD_NUM          3

#define APP_BUFFER_SIZE         256
#define BUFFER_SIZE             1024
#define UDP_BUFFER_SIZE         1024
#define TCP_BUFFER_SIZE         4096
#define DISCOVERY_STATE         100
#define PEERS_FOUND_STATE       101

using namespace std;

int udpState = DISCOVERY_STATE;
vector<Host*> myHosts;
map<int, Host*> tcpHosts;

struct pollfd fds[13];
int tcpConnections = 0;

char appBuffer[APP_BUFFER_SIZE];
char tempBuffer[APP_BUFFER_SIZE];
int appBufferLen = 0;

char myUsername[256];
char myPassword[256];
char myHostname[256];
char* anchorHost = NULL;
int myUDPPort = 50550;
int myTCPPort = 50551;
int myAnchorPort = 50552;
int minTimeout = 5; //in sec
int maxTimeout = 60; //in sec
bool directDiscover = false;

uint64_t myPublicKey = 0;
uint64_t myModulus = 0;
uint64_t myDecryptKey = 0;
uint64_t mySecretNum = 0;
bool authenticated = false;
bool auth_recvd = false;
bool ah_option = false;

Host* directedHost = NULL;
Host* lastConnectedHost = NULL;

char tcpReadBuffer[TCP_BUFFER_SIZE], tcpSendBuffer[TCP_BUFFER_SIZE];
char udpReadBuffer[UDP_BUFFER_SIZE], udpSendBuffer[UDP_BUFFER_SIZE];

void error(const char *message){
    perror(message);
    exit(0);
}

void printInHex(char* buffer, int len){
    for(int i = 0; i < len; i++){
        printf("%02x-%c ", buffer[i] & 0xff, buffer[i] & 0xff);
    }

    printf("\n");
}

void printInstructions(){
    cout << "Commands" << endl;
    cout << "/help - To see command list again" << endl;
    cout << "/mylist - To see who you can connect to." << endl;
    cout << "/connected - To see who you are connected with." << endl;
    cout << "/enc_connect NUM - Encryption Enabled version of \"/connect\"" << endl;
    cout << "/connect NUM - Connect to User NUM (Specified by the \"/mylist\" command)." << endl;
    cout << "/mess NUM - Direct messages at User NUM (Specified by the \"/mylist\" command)." << endl;
    cout << "/reqlist - Request user list from user you have directed messages at." << endl;
    cout << "/close NUM - Close TCP connection with User NUM (Specified by the \"/mylist\" command)." << endl;
    cout << "/exit - Close the program." << endl;
    cout << "Note: Make sure to check the mylist often as the user numbers will shift." << endl;
}

void printToConsole(const char* message){
    char tempBuffer2[APP_BUFFER_SIZE];
    
    if(directedHost != NULL){
        //add to string to temp buffer
        sprintf(tempBuffer2, "TX %s@%s> ", directedHost->username, directedHost->hostname);

        //erase the string from stdout
        for(int i = 0; i < strlen(tempBuffer2); i++){
            write(STDOUT_FILENO, "\b \b", 3);
        }
    }

    for(int i = 0; i < appBufferLen; i++){
        write(STDOUT_FILENO, "\b \b", 3);
    }

    write(STDOUT_FILENO, message, strlen(message));
    write(STDOUT_FILENO, "\n", 1);

    if(directedHost != NULL){
        write(STDOUT_FILENO, tempBuffer2, strlen(tempBuffer2));
    }

    write(STDOUT_FILENO, appBuffer, appBufferLen);

}

bool isNumber(char* num){
    if(num == NULL){
        return false;
    }
    //check for valid number
    for(int j = 0; j < strlen(num); j++){
        if(num[j] < 48 || num[j] > 57){
            return false;
        }
    }

    return true;
}

void printHostVector(){
    for(int i = 0; i < myHosts.size(); i++){
        myHosts[i]->debug();
    }
}

void SetNonCanonicalMode(int fd, struct termios *savedattributes){
    struct termios TermAttributes;
    char *name;
    
    // Make sure stdin is a terminal. 
    if(!isatty(fd)){
        fprintf (stderr, "Not a terminal.\n");
        exit(0);
    }
    
    // Save the terminal attributes so we can restore them later. 
    tcgetattr(fd, savedattributes);
    
    // Set the funny terminal modes. 
    tcgetattr (fd, &TermAttributes);
    TermAttributes.c_lflag &= ~(ICANON | ECHO); // Clear ICANON and ECHO. 
    TermAttributes.c_cc[VMIN] = 1;
    TermAttributes.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSAFLUSH, &TermAttributes);
}

bool insertIntoHostVector(Host* insertHost){
    bool saved = false;

    //check if recvhost entry has already been saved
    for(int i = 0; i < myHosts.size(); i++){
        if(*myHosts[i] == *insertHost){
            //cout << "Saved " << saved << endl;
            saved = true;
            break;
        }
    }

    if(!saved){
        //cout << "pushing hosts into the vector" << endl;
        myHosts.push_back(insertHost);
        return true;
    }

    return false;
}

void processUserListReply(Host* curHost){

    //continue reading next packets coming in, process the list entries
    if(0 > read(curHost->tcpFD, tcpReadBuffer, 4)){
        error("Error reading in");
    }

    // for(int i = 0; i < 4; i++){
    //     printf("%02x-%c ", tcpReadBuffer[i] & 0xff, tcpReadBuffer[i] & 0xff);
    // }
    printToConsole("Received User List");

    Host* insertHost;

    int numOfEntries = ntohl(*(int*)tcpReadBuffer), listEntLen, temp;

    //cout << "Number of Entries " << numOfEntries << endl;

    for(int i = 0; i < numOfEntries; i++){
        insertHost = new Host();

        listEntLen = 0;
        if(0 > read(curHost->tcpFD, tcpReadBuffer, 4)){
            error("Error reading in");
        }

        listEntLen+=4;

        if(0 > read(curHost->tcpFD, tcpReadBuffer+listEntLen, 2)){
            error("Error reading in");
        }

        //cout << "UDP Port " << ntohs(*(short*)(tcpReadBuffer+listEntLen)) << endl;
        insertHost->udpPort = ntohs(*(short*)(tcpReadBuffer+listEntLen));

        listEntLen+=2;
        temp = listEntLen;

        //cout << "Hostname ";

        //hostname
        do{
            if(0 > read(curHost->tcpFD, tcpReadBuffer+listEntLen, 1)){
                error("Error reading in");
            }
            //printf("%c", *(tcpReadBuffer+listEntLen));
        } while(tcpReadBuffer[listEntLen++] != '\0');

        //cout << endl;

        insertHost->hostname = (char*)malloc(listEntLen-temp);
        strcpy(insertHost->hostname, tcpReadBuffer+temp);

        if(0 > read(curHost->tcpFD, tcpReadBuffer+listEntLen, 2)){
            error("Error reading in");
        }

        //cout << "TCP Port " << ntohs(*(short*)(tcpReadBuffer+listEntLen)) << endl;
        insertHost->tcpPort = ntohs(*(short*)(tcpReadBuffer+listEntLen));

        listEntLen+=2;
        temp = listEntLen;

        //cout << "Username ";
        do{
            if(0 > read(curHost->tcpFD, tcpReadBuffer+listEntLen, 1)){
                error("Error reading in");
            }
            //printf("%c", *(tcpReadBuffer+listEntLen));
        } while(tcpReadBuffer[listEntLen++] != '\0');

        insertHost->username = (char*)malloc(listEntLen-temp);
        strcpy(insertHost->username, tcpReadBuffer+temp);
        //cout << endl;

        //cout << "----------------------------------------------------" << endl;

        int messLen = fillUDPMessage(udpSendBuffer, DISCOVERY_TYPE, myUDPPort, myTCPPort, myHostname, myUsername);

        Host myHostInfo(udpSendBuffer);

        sprintf(tempBuffer, "User %i %s@%s UDP %i TCP %i", i, insertHost->username, insertHost->hostname, insertHost->udpPort, insertHost->tcpPort);
        printToConsole(tempBuffer);

        //filter out own host
        if(!(*insertHost == myHostInfo) && !insertIntoHostVector(insertHost)){
            //cout << "found host in hostvector" << endl;
            delete insertHost;
        }
    }
}

Host* getHost(struct sockaddr* tcpClientAddress, int tcpClientLength){
    //get the host name
    char hbuf[100], sbuf[100];

    if (getnameinfo((struct sockaddr*) tcpClientAddress, tcpClientLength, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICSERV) != 0){
        error("Error on getting host name");
    }

    int j;
    //update the host and map Host pointer to the socketFD
    for(j = 0; j < myHosts.size(); j++){
        if(!(strcmp(myHosts[j]->hostname, hbuf)) && !(strcmp(myHosts[j]->username, tcpReadBuffer+6))){
            return myHosts[j];
        }
    }

    if(j == myHosts.size()){
        return NULL;
    }
}

Host* processEstablishMessage(int NewSockFD, struct sockaddr* tcpClientAddress, int tcpClientLength){
    fds[DEFAULT_FD_NUM+tcpConnections].fd = NewSockFD;
    fds[DEFAULT_FD_NUM+tcpConnections].events = POLLIN;

    tcpConnections++;

    //read for username
    int i = 5;

    do{
        i++;
        if(0 > read(NewSockFD, tcpReadBuffer+i, 1)){
            error("Error on reading from socket");
        }
    } while(tcpReadBuffer[i] != '\0');

    //get the host name
    char hbuf[100], sbuf[100];

    if (getnameinfo((struct sockaddr*) tcpClientAddress, tcpClientLength, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICSERV) != 0){
        error("Error on getting host name");
    }

    int j;
    //update the host and map Host pointer to the socketFD
    for(j = 0; j < myHosts.size(); j++){
        if(!(strcmp(myHosts[j]->hostname, hbuf)) && !(strcmp(myHosts[j]->username, tcpReadBuffer+6))){
            //found the host that sent me message
            // sprintf(tempBuffer, "%s@%s has connected to you!", myHosts[j]->username, myHosts[j]->hostname);
            // printToConsole(tempBuffer);
            
            myHosts[j]->tcpFD = NewSockFD;
            myHosts[j]->state = TCP_CONNECTED; //MAYBE PENDING INSTEAD?

            tcpHosts[NewSockFD] = myHosts[j];

            lastConnectedHost = myHosts[j];
            // sprintf(tempBuffer, "If you would like to reject the connection, type \"/reject\".");
            // printToConsole(tempBuffer);

            return myHosts[j];
            //break;
        }
    }

    if(j == myHosts.size()){
        return NULL;
        printToConsole("Unknown host tried to connect with you.");
        int tcpPacketLen = createTCPPacket(tcpSendBuffer, USER_UNAVAIBLABLE_TYPE, "");
        tcpHosts[NewSockFD]->sendPacketToHost(tcpSendBuffer, tcpPacketLen); 
    }
}

void parseCommand(char* buffer){
    //message
    if(buffer[0] != '/'){
        if(directedHost == NULL){
            printf("Please specify the receiver of the message with \"/mess\" command.\n");
        } else {
            if(!directedHost->encrypted){
                int packetLen = createTCPPacket(tcpSendBuffer, DATA_TYPE, buffer);
                directedHost->sendPacketToHost(tcpSendBuffer, packetLen);
            } else {
                //sending data chunk header
                int packetLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                directedHost->sendDataChunkHeader(tcpSendBuffer, packetLen);

                int bufferLen = strlen(buffer)+1;
                //sending payload
                *(short*)tcpSendBuffer = ntohs(DATA_ENCRYPT);

                //first 62 characters
                if(bufferLen >= 62){
                    strncpy(tcpSendBuffer+2, buffer, 62);
                } else{
                    strcpy(tcpSendBuffer+2, buffer);
                    GenerateRandomString((uint8_t*)(tcpSendBuffer+2+bufferLen), 64-bufferLen-2, directedHost->send_sequence);
                }

                buffer+=62;
                bufferLen-=62;

                PrivateEncryptDecrypt((uint8_t*)tcpSendBuffer, 64, directedHost->send_sequence);
                directedHost->sendPacketToHost(tcpSendBuffer, 64);

                if(bufferLen > 0){
                    //fragment further
                    while(bufferLen >= 64){
                        packetLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                        directedHost->sendDataChunkHeader(tcpSendBuffer, packetLen);
                        strncpy(tcpSendBuffer, buffer, 64);
                        PrivateEncryptDecrypt((uint8_t*)tcpSendBuffer, 64, directedHost->send_sequence);
                        directedHost->sendPacketToHost(tcpSendBuffer, 64);
                        buffer+=64;
                        bufferLen-=64;
                    }

                    //last fragment
                    packetLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                    directedHost->sendDataChunkHeader(tcpSendBuffer, packetLen);
                    strcpy(tcpSendBuffer, buffer);
                    GenerateRandomString((uint8_t*)(tcpSendBuffer+bufferLen), 64-bufferLen, directedHost->send_sequence);
                    PrivateEncryptDecrypt((uint8_t*)tcpSendBuffer, 64, directedHost->send_sequence);
                    directedHost->sendPacketToHost(tcpSendBuffer, 64);
                }
            }
        }

        return;
    }

    //commands
    char* token = strtok(buffer, " ");

    if(!strcmp(token, "/reqlist")){
        printf("Requesting user list.\n");
        //send request user packet
        if(directedHost != NULL){
            if(!directedHost->encrypted){
                int packetLen = createTCPPacket(tcpSendBuffer, REQUEST_USER_LIST_TYPE, NULL);
                directedHost->sendPacketToHost(tcpSendBuffer, packetLen);
            } else{
                printf("Encrypted request user.\n");
                // if(directedHost->receiver){
                //     directedHost->send_sequence++;
                // } else { directedHost->send_sequence--; }

                int packetLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                directedHost->sendDataChunkHeader(tcpSendBuffer, packetLen);

                *(uint16_t*)tcpSendBuffer = htons(REQUEST_UL_ENCRYPT);
                GenerateRandomString((uint8_t*)(tcpSendBuffer+2), 62, directedHost->send_sequence);

                PrivateEncryptDecrypt((uint8_t*)tcpSendBuffer, 64, directedHost->send_sequence);
                directedHost->sendPacketToHost(tcpSendBuffer, 64);
            }
        } else{ printf("Please specify the receiver of the message with \"/mess\" command.\n"); }
    } else if(!strcmp(token, "/mylist")){
        for(int i = 0; i < myHosts.size(); i++){
            myHosts[i]->printHost(i);
        }
    } else if(!strcmp(token, "/connect")){
        bool validNum = true;
        token = strtok(NULL, " ");

        for(int i = 0; i < strlen(token); i++){
            if(token[i] < 48 || token[i] > 57){
                validNum = false;
                break;
            }
        }

        if(validNum && atoi(token) < myHosts.size()){
            int hostTCPfd = myHosts[atoi(token)]->TCPConnectToHost();

            if(hostTCPfd == -2) {
                printf("You are already connected to this host.\n");
            } else if(hostTCPfd > 0){
                fds[DEFAULT_FD_NUM+tcpConnections].fd = hostTCPfd;
                fds[DEFAULT_FD_NUM+tcpConnections].events = POLLIN;

                tcpConnections++;

                printf("Connecting to %s@%s...\n", myHosts[atoi(token)]->username, myHosts[atoi(token)]->hostname);
                //send establish packet
                int packetLen = createTCPPacket(tcpSendBuffer, ESTABLISH_COM_TYPE, myUsername);
                myHosts[atoi(token)]->sendPacketToHost(tcpSendBuffer, packetLen);

                //myHosts[atoi(token)]->state = TCP_PENDING;

                //ADD HOST TO MAP
                tcpHosts[hostTCPfd] = myHosts[atoi(token)];
            } else { printf("Error connecting to this host.\n"); }
        } else{ printf("Invalid host.\n"); }
    } else if(!strcmp(token, "/enc_connect")){
        bool validNum = true;
        token = strtok(NULL, " ");

        for(int i = 0; i < strlen(token); i++){
            if(token[i] < 48 || token[i] > 57){
                validNum = false;
                break;
            }
        }

        if(validNum && atoi(token) < myHosts.size()){
            int hostTCPfd = myHosts[atoi(token)]->TCPConnectToHost();

            if(hostTCPfd == -2) {
                printf("You are already connected to this host.\n");
            } else if(hostTCPfd > 0){
                fds[DEFAULT_FD_NUM+tcpConnections].fd = hostTCPfd;
                fds[DEFAULT_FD_NUM+tcpConnections].events = POLLIN;

                tcpConnections++;

                printf("Establishing encrypted connection to %s@%s...\n", myHosts[atoi(token)]->username, myHosts[atoi(token)]->hostname);
                //send establish packet
                int packetLen = createEstablishEncryptCom(tcpSendBuffer, myUsername, myPublicKey, myModulus);
                myHosts[atoi(token)]->sendPacketToHost(tcpSendBuffer, packetLen);

                //myHosts[atoi(token)]->state = TCP_PENDING;

                //ADD HOST TO MAP
                tcpHosts[hostTCPfd] = myHosts[atoi(token)];
            } else { printf("Error connecting to this host.\n"); }
        } else{ printf("Invalid host.\n"); }
    } else if(!strcmp(token, "/mess")){
        //can only message someone I have connected to
        token = strtok(NULL, " ");

        if(isNumber(token) && atoi(token) < myHosts.size()){
            try{
                directedHost = tcpHosts.at(myHosts[atoi(token)]->tcpFD);
                printf("Now talking to %s@%s at TCP Port %i.\n", directedHost->username, directedHost->hostname, directedHost->tcpPort);
            } catch( const std::out_of_range& oor){
                printf("Please use the \"/connect\" to connect to the receiver before messaging them.\n");
            }
        } else{ printf("Invalid host.\n"); }
    } else if(!strcmp(token, "/close")){
        //close connection for user X
        token = strtok(NULL, " ");

        if(isNumber(token) && atoi(token) < myHosts.size()) {
            Host *tempHost = myHosts[atoi(token)];

            if(tempHost->state != TCP_NOT_CONNECTED){
                printf("Closing TCP connection...\n");
                //send close message
                if(!tempHost->encrypted){
                    int messLen = createTCPPacket(tcpSendBuffer, DISCONTINUE_COM_TYPE, "");
                    tempHost->sendPacketToHost(tcpSendBuffer, messLen);
                } else{
                    int messLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                    tempHost->sendDataChunkHeader(tcpSendBuffer, messLen);

                    *(short*)tcpSendBuffer = DISCONT_COM_ENCRYPT;
                    GenerateRandomString((uint8_t*)(tcpSendBuffer+2), 62, tempHost->send_sequence);

                    PrivateEncryptDecrypt((uint8_t*)tcpSendBuffer, 64, tempHost->send_sequence);
                    tempHost->sendPacketToHost(tcpSendBuffer, 64);
                }

                //find the tcpFD in the fds array to delete
                for(int i = 0; i < tcpConnections; i++){
                    if(fds[DEFAULT_FD_NUM+i].fd == tempHost->tcpFD){
                        tempHost->closeConnection(&tcpConnections, i, fds, &tcpHosts);
                        printf("Connection closed.\n");
                        break;
                    }
                }

                //tempHost->printHost(-1);
                //directedHost->printHost(0);

                if(directedHost != NULL && *tempHost == *directedHost){
                    directedHost = NULL;
                }
            } else{ printf("You are not connected to this host.\n"); }
        } else{ printf("Invalid host.\n"); }
    } else if(!strcmp(token, "/connected")){
        bool haveConnections = false;
        for(int i =0; i < myHosts.size(); i++){
            if(myHosts[i]->state == TCP_CONNECTED){
                myHosts[i]->printHost(i);
                haveConnections = true;
            }
        }

        if(!haveConnections){
            printf("No connections found.\n");
        }
    } else if(!strcmp(token, "/reject")){
        if(lastConnectedHost != NULL){
            if(!lastConnectedHost->encrypted){
                int messLen = createTCPPacket(tcpSendBuffer, USER_UNAVAIBLABLE_TYPE, "");
                lastConnectedHost->sendPacketToHost(tcpSendBuffer, messLen);
            } else{
                int messLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                lastConnectedHost->sendDataChunkHeader(tcpSendBuffer, messLen);

                *(short*)tcpSendBuffer = ntohs(USER_UNAVAIL_ENCRYPT);
                GenerateRandomString((uint8_t*)(tcpSendBuffer+2), 62, lastConnectedHost->send_sequence);

                PrivateEncryptDecrypt((uint8_t*)tcpSendBuffer, 64, lastConnectedHost->send_sequence);
                lastConnectedHost->sendPacketToHost(tcpSendBuffer, 64);
            }

            printf("Rejected connection.\n");
            for(int i = 0; i < tcpConnections; i++){
                if(fds[DEFAULT_FD_NUM+i].fd == lastConnectedHost->tcpFD){
                    lastConnectedHost->closeConnection(&tcpConnections, i, fds, &tcpHosts);
                    break;
                }
            }

            lastConnectedHost = NULL;
        } else{ printf("No last connection found.\n"); }
    } else if(!strcmp(token, "/exit")){
        struct sockaddr_in BServerAddress;
        int Result;
        for(int i = 0; i < myHosts.size(); i++){
            if(myHosts[i]->state != TCP_NOT_CONNECTED){
                int messLen = createTCPPacket(tcpSendBuffer, DISCONTINUE_COM_TYPE, "");
                myHosts[i]->sendPacketToHost(tcpSendBuffer, messLen);
                close(myHosts[i]->tcpFD);
            }
        }

        //close TCP server FD
        close(fds[1].fd);

        // Setup BServerAddress data structure for broadcast
        bzero((char *) &BServerAddress, sizeof(BServerAddress));
        BServerAddress.sin_family = AF_INET;
        BServerAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        BServerAddress.sin_port = htons(myUDPPort);

        char Buffer[BUFFER_SIZE];
        int messLen = fillUDPMessage(Buffer, CLOSING_TYPE, myUDPPort, myTCPPort, myHostname, myUsername);

        //sending the first discovery message on start up
        Result = sendto(fds[0].fd, Buffer, messLen , 0, (struct sockaddr *)&BServerAddress, sizeof(BServerAddress));
        if(0 > Result){ 
            error("ERROR sending to server");
        }

        close(fds[0].fd);

        exit(0);
    } else if(!strcmp(token, "/help")) {
        printInstructions();
    } else{
        printf("Invalid Command.\n");
    }
}

void parseOptions(int argc, char **argv){
    for(int i = 1; i < argc; i++){
        if(!strcmp(argv[i], "-u")){
            strcpy(myUsername, argv[++i]);
        } else if(!strcmp(argv[i], "-up")){
            if(isNumber(argv[++i])){
                int tempPort = atoi(argv[i]);

                if(tempPort < 1 || tempPort > 65535){
                    printf("UDP Port Invalid");
                    exit(0);
                } else{ myUDPPort = tempPort; }

            } else { 
                printf("UDP Port Invalid\n"); 
                exit(0);
            }
        } else if(!strcmp(argv[i], "-tp")){
            if(isNumber(argv[++i])){
                int tempPort = atoi(argv[i]);

                if(tempPort < 1 || tempPort > 65535){
                    printf("TCP Port Invalid\n");
                    exit(0);
                } else{ myTCPPort = tempPort; }

            } else { 
                printf("TCP Port Invalid\n"); 
                exit(0);
            }
        } else if(!strcmp(argv[i], "-dt")) {
            if(isNumber(argv[++i])){
                minTimeout = atoi(argv[i]);
            } else{ 
                printf("Invalid Min Timeout\n"); 
                exit(0);
            }
        } else if(!strcmp(argv[i], "-dm")) {
            if(isNumber(argv[++i])){
                maxTimeout = atoi(argv[++i]);
            } else{ 
                printf("Invalid Max Timeout."); 
                exit(0);
            }
        } else if(!strcmp(argv[i], "-pp")){
            strcpy(tempBuffer, argv[++i]);
            directDiscover = true;
        } else if(!strcmp(argv[i], "-ap")){
            if(!ah_option){
                if(isNumber(argv[++i])){
                    int tempPort = atoi(argv[i]);

                    if(tempPort < 1 || tempPort > 65535){
                        printf("Anchor Port Invalid\n");
                        exit(0);
                    } else{ myAnchorPort = tempPort; }
                }
            }
        } else if(!strcmp(argv[i], "-ah")){
            char* token = strtok(argv[++i], ":");
            anchorHost = (char*)malloc(strlen(token)+1);
            strcpy(anchorHost, token);

            token = strtok(NULL, ":");

            if(token != NULL){
                ah_option = true;
                if(isNumber(token)){
                    int tempPort = atoi(token);

                    if(tempPort < 1 || tempPort > 65535){
                        printf("Anchor Port Invalid\n");
                        exit(0);
                    } else{ myAnchorPort = tempPort; }
                }
            }
        }
    }
}

void sighandler(int sig_num){
    if(sig_num == SIGINT){
        struct sockaddr_in BServerAddress;
        int Result;

        for(int i = 0; i < myHosts.size(); i++){
            if(myHosts[i]->state != TCP_NOT_CONNECTED){
                if(!myHosts[i]->encrypted){
                    int messLen = createTCPPacket(tcpSendBuffer, DISCONTINUE_COM_TYPE, "");
                    myHosts[i]->sendPacketToHost(tcpSendBuffer, messLen);
                } else {
                    int messLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                    myHosts[i]->sendDataChunkHeader(tcpSendBuffer, messLen);

                    *(short*)tcpSendBuffer = DISCONT_COM_ENCRYPT;
                    GenerateRandomString((uint8_t*)(tcpSendBuffer+2), 62, myHosts[i]->send_sequence);

                    PrivateEncryptDecrypt((uint8_t*)tcpSendBuffer, 64, myHosts[i]->send_sequence);
                    myHosts[i]->sendPacketToHost(tcpSendBuffer, 64);
                }
                close(myHosts[i]->tcpFD);
            }
        }

        //close TCP server FD
        close(fds[1].fd);

        // Setup BServerAddress data structure for broadcast
        bzero((char *) &BServerAddress, sizeof(BServerAddress));
        BServerAddress.sin_family = AF_INET;
        BServerAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        BServerAddress.sin_port = htons(myUDPPort);

        char Buffer[BUFFER_SIZE];
        int messLen = fillUDPMessage(Buffer, CLOSING_TYPE, myUDPPort, myTCPPort, myHostname, myUsername);

        Result = sendto(fds[0].fd, Buffer, messLen , 0, (struct sockaddr *)&BServerAddress, sizeof(BServerAddress));
        if(0 > Result){ 
            error("ERROR sending to server");
        }

        close(fds[0].fd);

        exit(0);
    }
}

void alarmHandler(int sig){
    char sendBuffer[64];
    for(int i = 0; i < myHosts.size(); i++){
        if(myHosts[i]->state == TCP_CONNECTED && myHosts[i]->encrypted){
            //printToConsole("Sending dummy message.");
            //send dummy packet
            int messLen = createTCPPacket(sendBuffer, ENCRYPTED_DATA_CHUNK, "");
            myHosts[i]->sendDataChunkHeader(sendBuffer, messLen);

            *(uint16_t*)sendBuffer = htons(DUMMY);
            GenerateRandomString((uint8_t*)(sendBuffer+2), 62, myHosts[i]->send_sequence);
            PrivateEncryptDecrypt((uint8_t*)sendBuffer, 64, myHosts[i]->send_sequence);
            myHosts[i]->sendPacketToHost(sendBuffer, 64);
        }
    }

    uint64_t randNum = GenerateRandomValue();
    alarm(randNum%30);
}

void displayChar(char curChar, bool password){
    if(curChar == '\n'){
        write(STDOUT_FILENO, "\n", 1);
    }
    else if(curChar == 0x7f){ //backspace
        if(appBufferLen != 0){
            appBufferLen--;
            write(STDOUT_FILENO, "\b \b", 3);
        } else{ 
            //write bell character to indicate invalid
            curChar = 0x07;
            write(STDOUT_FILENO, &curChar, 1); 
        }
    } else if(curChar == 0x1B){
        //throw away next character
        read(STDIN_FILENO, &curChar, 1);
        read(STDIN_FILENO, &curChar, 1);
        curChar = 0x7;
        write(STDOUT_FILENO, &curChar, 1);
    } else if(curChar > 31){
        if(!password){
            write(STDOUT_FILENO, &curChar, 1);
        } else {
            write(STDOUT_FILENO, "*", 1);
        }
        //printf("%c", *(appBuffer+appBufferLen));
        appBufferLen++;
    }
}

//int SocketFileDescriptor;

/*void SignalHandler(int param){
    close(SocketFileDescriptor);
    exit(0);
}*/

int main(int argc, char *argv[]){
    int SocketFileDescriptor, NewSockFD, AnchorFD, tcpSocketFD, PortNumber;
    socklen_t ClientLength, AnchorClientLength, tcpClientLength, BroadcastEnable;
    char Buffer[BUFFER_SIZE];
    struct sockaddr_in BServerAddress, AnchorBServerAddress, AnchorServerAddress, ServerAddress, tcpServerAddress, ClientAddress, tcpClientAddress, AnchorClientAddress;
    int Result;
    int messLen;

    struct in_addr ThisAddress, ThisMask;
    char AddressBuffer[256];

    struct termios SavedTermAttributes;
    char RXChar;
    
    signal(SIGINT, sighandler);
    signal(SIGALRM, alarmHandler);
    alarm(GenerateRandomValue()%20);
    SetNonCanonicalMode(STDIN_FILENO, &SavedTermAttributes);
    
    strcpy(myUsername, getenv("USER"));

    if(0 == GetLocalhostInformation(myHostname, &ThisAddress, &ThisMask)){
        //inet_ntop(AF_INET, &ThisAddress, AddressBuffer, INET_ADDRSTRLEN);
        //printf("Hostname = %s\nIP = %s ",ThisName, AddressBuffer);
        //inet_ntop(AF_INET, &ThisMask, AddressBuffer, INET_ADDRSTRLEN);
        //printf("Mask = %s\n", AddressBuffer);
    }
    else{
        printf("Error calling GetLocalhostInformation\n");
    }

    parseOptions(argc, argv);

    //reading in password
    write(STDOUT_FILENO, "Password: ", 10);

    do{
        read(STDIN_FILENO, appBuffer+appBufferLen, 1);
        displayChar(appBuffer[appBufferLen], true);
    } while (appBuffer[appBufferLen] != '\n');

    //program start info
    cout << "Username = " << myUsername << endl;
    cout << "Hostname = " << myHostname << endl;
    cout << "UDP Port = " << myUDPPort << endl;
    cout << "TCP Port = " << myTCPPort << endl;
    cout << "Anchor Port = " << myAnchorPort << endl;
    cout << "Mintimeout = " << minTimeout << "s" << endl;
    cout << "Maxtimeout = " << maxTimeout << "s" << endl << endl;;

    if(anchorHost != NULL){
        cout << "Specified Anchor: " << anchorHost << endl;
    }

    appBuffer[appBufferLen] = '\0';

    strcpy(myPassword, appBuffer);
    appBufferLen = 0;

    //generate my keys on the fly
    strcpy(appBuffer, myUsername);
    strcat(appBuffer, ":");
    strcat(appBuffer, myPassword);
    StringToPublicNED(appBuffer, myModulus, myPublicKey, myDecryptKey);

    printInstructions();

    cout << endl;

    // Create UDP/IP socket
    SocketFileDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(0 > SocketFileDescriptor){
        error("ERROR opening socket");
    }

    // Create TCP/IP socket
    tcpSocketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(0 > tcpSocketFD){
        error("ERROR opening socket");
    }

    // AnchorFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    // if(0 > AnchorFD){
    //     error("ERROR opening socket");
    // }

    // Setup ServerAddress data structure
    bzero((char *) &ServerAddress, sizeof(ServerAddress));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = INADDR_ANY;
    ServerAddress.sin_port = htons(myUDPPort);

    // Setup ServerAddress data structure for tcp 
    bzero((char *) &tcpServerAddress, sizeof(tcpServerAddress));
    tcpServerAddress.sin_family = AF_INET;
    tcpServerAddress.sin_addr.s_addr = INADDR_ANY;
    tcpServerAddress.sin_port = htons(myTCPPort);

    //Setup ServerAddress data structure
    // bzero((char *) &AnchorServerAddress, sizeof(AnchorServerAddress));
    // AnchorServerAddress.sin_family = AF_INET;
    // AnchorServerAddress.sin_addr.s_addr = INADDR_ANY;
    // AnchorServerAddress.sin_port = htons(myAnchorPort);

    // Setup BServerAddress data structure for broadcast
    bzero((char *) &BServerAddress, sizeof(BServerAddress));
    BServerAddress.sin_family = AF_INET;
    BServerAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    BServerAddress.sin_port = htons(myUDPPort);

    // Setup AnchorBServerAddress data structure for broadcast
    bzero((char *) &AnchorBServerAddress, sizeof(AnchorBServerAddress));
    AnchorBServerAddress.sin_family = AF_INET;
    AnchorBServerAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    AnchorBServerAddress.sin_port = htons(myAnchorPort);

    // Set UDP sockets to enable broadcast
    BroadcastEnable = 1;
    Result = setsockopt(SocketFileDescriptor, SOL_SOCKET, SO_BROADCAST, &BroadcastEnable, sizeof(BroadcastEnable));
    if(0 > Result){
        close(SocketFileDescriptor);
        error("ERROR setting socket option");
    }

    // Binding socket to port
    if(0 > bind(SocketFileDescriptor, (struct sockaddr *)&ServerAddress, sizeof(ServerAddress))){ 
        error("ERROR on binding");
    }
    ClientLength = sizeof(ClientAddress);
    bzero(Buffer, BUFFER_SIZE);

    // Binding socket to port
    if(0 > bind(tcpSocketFD, (struct sockaddr *)&tcpServerAddress, sizeof(tcpServerAddress))){ 
        error("ERROR on binding");
    }

    // Listening for clients
    listen(tcpSocketFD, 5);
    tcpClientLength = sizeof(tcpClientAddress);


    messLen = fillUDPMessage(Buffer, DISCOVERY_TYPE, myUDPPort, myTCPPort, myHostname, myUsername);

    Host myHostInfo(Buffer);

    int timeout_msecs = minTimeout*1000;
    int poll_status;

    fds[0].fd = SocketFileDescriptor;
    fds[0].events = POLLIN;
    fds[1].fd = tcpSocketFD;
    fds[1].events = POLLIN;
    fds[2].fd = STDIN_FILENO;
    fds[2].events = POLLIN;

    if(!directDiscover){
        //sending the first discovery message on start up
        Result = sendto(SocketFileDescriptor, Buffer, messLen , 0, (struct sockaddr *)&BServerAddress, sizeof(BServerAddress));
        if(0 > Result){ 
            error("ERROR sending to server");
        }
    } else {
        //send discover to host specified by the -pp
        struct sockaddr_in client_addr;
        struct hostent *Server;
        char* token = strtok(tempBuffer, ":");

        // Convert/resolve host name 
        Server = gethostbyname(token);
        if(NULL == Server){
            fprintf(stderr,"ERROR, no such host\n");
            exit(0);
        }

        token = strtok(NULL, ":");

        if(!isNumber(token)){
            error("Invalid Port Number in direct discover");
        }

        //setup server address
        bzero((char *) &client_addr, sizeof(client_addr));
        client_addr.sin_family = AF_INET;
        bcopy((char *)Server->h_addr, (char *)&client_addr.sin_addr.s_addr, Server->h_length);
        client_addr.sin_port = htons(atoi(token));

        Result = sendto(SocketFileDescriptor, Buffer, messLen, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if(0 > Result){ 
            error("ERROR sending to server");
        }
    }

    //create authentication request
    mySecretNum = GenerateRandomValue() & 0xffffffff;
    uint64_t tempSecretNum = mySecretNum;
    PublicEncryptDecrypt(tempSecretNum, P2PI_TRUST_E, P2PI_TRUST_N);

    messLen = createReqAuthKeyMess(udpSendBuffer, tempSecretNum, myUsername);

    printToConsole("Sending Authentication Request for Self.");

    if(anchorHost == NULL){
        //sending the first authentication message on start up
        Result = sendto(SocketFileDescriptor, udpSendBuffer, messLen , 0, (struct sockaddr *)&AnchorBServerAddress, sizeof(AnchorBServerAddress));
        if(0 > Result){ 
            error("ERROR sending to server");
        }
    } else{
        sprintf(tempBuffer, "Sending authentication Request to %s.", anchorHost);
        printToConsole(tempBuffer);
        struct hostent *Server;

        // Convert/resolve host name 
        Server = gethostbyname(anchorHost);
        if(NULL == Server){
            fprintf(stderr,"ERROR, no such host\n");
            exit(0);
        }

        //setup server address
        bzero((char *) &AnchorServerAddress, sizeof(AnchorServerAddress));
        AnchorServerAddress.sin_family = AF_INET;
        bcopy((char *)Server->h_addr, (char *)&AnchorServerAddress.sin_addr.s_addr, Server->h_length);
        AnchorServerAddress.sin_port = htons(myAnchorPort);

        Result = sendto(SocketFileDescriptor, udpSendBuffer, messLen, 0, (struct sockaddr *)&AnchorServerAddress, sizeof(AnchorServerAddress));
        if(0 > Result){ 
            error("ERROR sending to server");
        }
    }

    while(1){
        poll_status = poll(fds, DEFAULT_FD_NUM+tcpConnections, timeout_msecs);

        if(poll_status < 0) {
            if(errno != EINTR){
                error("Poll Error");
            }
        }
        else if(poll_status == 0){
            //timeout
            if(directDiscover){
                printf("No more connections can be found. Type \"exit\" to close the program.\n");
            }
            else if(udpState == DISCOVERY_STATE){
                printToConsole("Sending discovery.");
                if(timeout_msecs < maxTimeout*1000){
                    timeout_msecs *= 2;
                }

                bzero(Buffer, BUFFER_SIZE);
                messLen = fillUDPMessage(Buffer, DISCOVERY_TYPE, myUDPPort, myTCPPort, myHostname, myUsername);
                Result = sendto(SocketFileDescriptor, Buffer, messLen , 0, (struct sockaddr *)&BServerAddress, sizeof(BServerAddress));
                
                if(0 > Result){ 
                    error("ERROR sending to server");
                }
            } else {
                //send authentication message for timed out auth requests
                //TODO: change timeout time
                if(!auth_recvd){
                    printToConsole("Sending Authentication Request for Self");
                    messLen = createReqAuthKeyMess(udpSendBuffer, tempSecretNum, myUsername);

                    if(anchorHost == NULL){
                        Result = sendto(SocketFileDescriptor, udpSendBuffer, messLen , 0, (struct sockaddr *)&AnchorBServerAddress, sizeof(AnchorBServerAddress));
                    } else{
                        Result = sendto(SocketFileDescriptor, udpSendBuffer, messLen, 0, (struct sockaddr *)&AnchorServerAddress, sizeof(AnchorServerAddress));
                    }

                    if(0 > Result){ 
                        error("ERROR sending to server");
                    } 
                }
                for(int i = 0; i < myHosts.size(); i++){
                    if(!myHosts[i]->auth_recvd){
                        sprintf(tempBuffer, "Sending Authentication Request for %s", myHosts[i]->username);
                        printToConsole(tempBuffer);
                        uint64_t encSecretNum = myHosts[i]->secretNum;

                        PublicEncryptDecrypt(encSecretNum, P2PI_TRUST_E, P2PI_TRUST_N);
                        messLen = createReqAuthKeyMess(udpSendBuffer, encSecretNum, myHosts[i]->username);
                        
                        if(anchorHost == NULL){
                            Result = sendto(SocketFileDescriptor, udpSendBuffer, messLen , 0, (struct sockaddr *)&AnchorBServerAddress, sizeof(AnchorBServerAddress));
                        } else{
                            Result = sendto(SocketFileDescriptor, udpSendBuffer, messLen, 0, (struct sockaddr *)&AnchorServerAddress, sizeof(AnchorServerAddress));
                        }

                        if(0 > Result){ 
                            error("ERROR sending to server");
                        }
                    }
                }
            }
        }
        else if (poll_status > 0){
            //UDP socket
            if(fds[0].revents && POLLIN) {
                // printf("Received in UDP socket\n");
                //received broadcast message
                Result = recvfrom(SocketFileDescriptor, Buffer, BUFFER_SIZE, 0, (struct sockaddr *)&ClientAddress, &ClientLength);
                if(0 > Result){
                    error("ERROR receive from client");
                }

                // printf("Type: %d\n", ntohs(*(short*)(Buffer + 4)));

                //decode message type
                if(ntohs(*(short*)(Buffer + 4)) == CLOSING_TYPE){
                    Host recvHost(Buffer);

                    for(int i = 0;i < myHosts.size(); i++){
                        if(*myHosts[i] == recvHost){
                            if(myHosts[i]->state != TCP_NOT_CONNECTED){
                                for(int j = 0; j < tcpConnections; j++){
                                    if(myHosts[i]->tcpFD == fds[DEFAULT_FD_NUM+j].fd){
                                        myHosts[i]->closeConnection(&tcpConnections, j, fds, &tcpHosts);
                                        break;
                                    }
                                }
                            }

                            if(directedHost != NULL && *myHosts[i] == *directedHost){
                                directedHost = NULL;
                            }

                            myHosts.erase(myHosts.begin() + i);
                            break;
                        }
                    }

                    if(myHosts.size() == 0){
                        udpState = DISCOVERY_STATE;
                    }
                }
                else if(ntohs(*(short*)(Buffer + 4)) == REQ_AUTH_REPLY_TYPE){
                    uint64_t repliedSecretNum, pub_key, mod, checksum;
                    char * repliedUser = Buffer + 14;
                    
                    int messLen = 14;
                    repliedSecretNum = ntohll(*(uint64_t*)(Buffer+6));

                    // printf("Username: %s\n", Buffer+14);
                    messLen+=(strlen(Buffer+14) + 1);

                    pub_key = ntohll(*(uint64_t*)(Buffer+messLen));
                    // printf("Public Key: %llu\n", pub_key);
                    messLen+=8;

                    mod = ntohll(*(uint64_t*)(Buffer+messLen));
                    // printf("Modulus: %llu\n", mod);
                    messLen+=8;

                    checksum = ntohll(*(uint64_t*)(Buffer+messLen));

                    PublicEncryptDecrypt(checksum, P2PI_TRUST_E, P2PI_TRUST_N);
                    PublicEncryptDecrypt(repliedSecretNum, P2PI_TRUST_E, P2PI_TRUST_N);

                    if(checksum == AuthenticationChecksum(repliedSecretNum&0xFFFFFFFF, repliedUser, pub_key, mod)){
                        //printf("Checksum checked out.\n");
                        //check if the authority replied to my authority request
                        if(!strcmp(repliedUser, myUsername)){
                            if(repliedSecretNum == mySecretNum){
                                if(myPublicKey == pub_key && myModulus == mod){
                                    printf("Password provided has been authenticated.\n");
                                    authenticated = true;
                                } else if(pub_key == 0 && mod == 0){
                                    printf("Trust anchor does not have info on you.\n");
                                } else{ printf("Password provided does not match the trust anchor.\n", myUsername); }

                                auth_recvd = true;
                            }
                        }

                        //check if trust anchor replied to authority request for one of the other hosts
                        for(int i=0; i < myHosts.size(); i++){
                            if(!strcmp(myHosts[i]->username, repliedUser)){
                                if(repliedSecretNum == myHosts[i]->secretNum && !myHosts[i]->auth_recvd){
                                    myHosts[i]->trust_pub_key = pub_key;
                                    myHosts[i]->trust_mod = mod;
                                    myHosts[i]->auth_recvd = true;

                                    if(pub_key == 0 && mod == 0){
                                        sprintf(tempBuffer, "User %s, unknown by authority.", myHosts[i]->username);
                                    } else {
                                        myHosts[i]->authenticated = true;
                                        sprintf(tempBuffer ,"User %s, authenticated.", myHosts[i]->username);
                                    }

                                    printToConsole(tempBuffer);
                                } 
                            }
                        }
                    } else{ printf("Invalid checksum.\n"); }
                } 
                else{
                    //discovery or reply
                    bool saved = false;
                    Host *recvHost = new Host(Buffer);

                    bool isMyHost = (myHostInfo == *recvHost);

                    //filter out my host info
                    if(!(myHostInfo == *recvHost)){
                        //insert into host vector
                        if(!insertIntoHostVector(recvHost)){
                            delete recvHost;
                        } else {
                            sprintf(tempBuffer, "Sending authentication request for %s", recvHost->username);
                            printToConsole(tempBuffer);
                            recvHost->secretNum = GenerateRandomValue() & 0xffffffff;
                            uint64_t encSecretNum = recvHost->secretNum;

                            PublicEncryptDecrypt(encSecretNum, P2PI_TRUST_E, P2PI_TRUST_N);

                            messLen = createReqAuthKeyMess(udpSendBuffer, encSecretNum, recvHost->username);
                            Result = sendto(SocketFileDescriptor, udpSendBuffer, messLen , 0, (struct sockaddr *)&AnchorBServerAddress, sizeof(AnchorBServerAddress));
                            if(0 > Result){ 
                                error("ERROR sending to server");
                            }
                        }

                        if(ntohs(*(short*)(Buffer + 4)) == DISCOVERY_TYPE){ 
                            //printToConsole("Inside Discovery\n");
                            //send unicast reply back to discovery sender
                            messLen = fillUDPMessage(Buffer, REPLY_TYPE, myUDPPort, myTCPPort, myHostname, myUsername);
                            Result = sendto(SocketFileDescriptor, Buffer, messLen , 0, (struct sockaddr *)&ClientAddress, ClientLength);

                            if(0 > Result){ 
                                error("ERROR sending reply message");
                            }
                        }
                    }

                    if(myHosts.size() > 0){
                        udpState = PEERS_FOUND_STATE;
                        //set timeout for sending authentication requests
                        timeout_msecs = 10 * 1000;
                    }
                }
            }
        }

        //TCP socket
        if(fds[1].revents && POLLIN){
            if(tcpConnections < MAX_TCP_CONNECTIONS){
                //add the tcp connection to tcpHosts
                NewSockFD = accept(tcpSocketFD, (struct sockaddr*) &tcpClientAddress, &tcpClientLength);
                if(NewSockFD < 0){
                    error("Error on accept");
                }

                //read for establish message
                if(0 > read(NewSockFD, tcpReadBuffer, 6)){
                    error("Error on reading from socket");
                }

                if(ntohs(*(short*)(tcpReadBuffer+4)) == ESTABLISH_COM_TYPE){
                    //cout << "Iinside establish communication" << endl;
                    //add connection to fds to poll
                    fds[DEFAULT_FD_NUM+tcpConnections].fd = NewSockFD;
                    fds[DEFAULT_FD_NUM+tcpConnections].events = POLLIN;

                    tcpConnections++;

                    //read for username
                    int i = 5;

                    do{
                        i++;
                        if(0 > read(NewSockFD, tcpReadBuffer+i, 1)){
                            error("Error on reading from socket");
                        }
                    } while(tcpReadBuffer[i] != '\0');

                    //get the host name
                    char hbuf[100], sbuf[100];

                    if (getnameinfo((struct sockaddr*) &tcpClientAddress, tcpClientLength, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICSERV) != 0){
                        error("Error on getting host name");
                    }

                    int j;
                    //update the host and map Host pointer to the socketFD
                    for(j = 0; j < myHosts.size(); j++){
                        if(!(strcmp(myHosts[j]->hostname, hbuf)) && !(strcmp(myHosts[j]->username, tcpReadBuffer+6))){
                            //found the host that sent me message
                            sprintf(tempBuffer, "%s@%s has connected to you!", myHosts[j]->username, myHosts[j]->hostname);
                            printToConsole(tempBuffer);
                            //TODO: WOULD U LIEK TO CONNECT BACK?
                            myHosts[j]->tcpFD = NewSockFD;
                            myHosts[j]->state = TCP_CONNECTED; //MAYBE PENDING INSTEAD?

                            tcpHosts[NewSockFD] = myHosts[j];

                            lastConnectedHost = myHosts[j];
                            sprintf(tempBuffer, "If you would like to reject the connection, type \"/reject\".");
                            printToConsole(tempBuffer);
                            break;
                        }
                    }

                    if(j == myHosts.size()){
                        printToConsole("Unknown host tried to connect with you.");
                        int tcpPacketLen = createTCPPacket(tcpSendBuffer, USER_UNAVAIBLABLE_TYPE, "");
                        tcpHosts[NewSockFD]->sendPacketToHost(tcpSendBuffer, tcpPacketLen); 
                    }

                    //send accept message
                    int tcpPacketLen = createTCPPacket(tcpSendBuffer, ACCEPT_CM_TYPE, "");
                    tcpHosts[NewSockFD]->sendPacketToHost(tcpSendBuffer, tcpPacketLen); 
                } else if(ntohs(*(short*)(tcpReadBuffer+4)) == ESTABLISH_ENCRYPTED_COM) {
                    printf("Received establish_encrypted_com\n");
                    Host* tempHost = processEstablishMessage(NewSockFD, (struct sockaddr*)&tcpClientAddress, tcpClientLength);

                    //read in the public key and modulus
                    if(read(NewSockFD, tcpReadBuffer, 16) < 0){
                        error("Error on reading from socket");
                    }
                    
                    if(tempHost != NULL){
                        //tempHost->printHost(0);
                        tempHost->pub_key = ntohll(*(uint64_t*)tcpReadBuffer);
                        tempHost->mod = ntohll(*(uint64_t*)(tcpReadBuffer+8));
                        tempHost->encrypted = true;

                        sprintf(tempBuffer, "%s@%s has established an encrypted connection to you!", tempHost->username, tempHost->hostname);
                        printToConsole(tempBuffer);

                        if(tempHost->checkAuthentication() == AUTH){
                            sprintf(tempBuffer, "%s@%s is authentic.", tempHost->username, tempHost->hostname);
                        } else { sprintf(tempBuffer, "%s@%s is not verified.", tempHost->username, tempHost->hostname); }

                        printToConsole(tempBuffer);

                        sprintf(tempBuffer, "Type \"/reject\" to decline encrypted connection.");
                        printToConsole(tempBuffer);

                        //send accept communication message
                        //generate random number and encrypt high 32 bits and low 32 bits
                        tempHost->recv_sequence = (tempHost->send_sequence = GenerateRandomValue());
                        tempHost->receiver = false;
                        tempHost->encrypted = true;

                        uint64_t sequence_high, sequence_low;

                        sequence_low = tempHost->recv_sequence & 0xFFFFFFFF;
                        sequence_high = tempHost->send_sequence >> 32;

                        PublicEncryptDecrypt(sequence_low, tempHost->pub_key, tempHost->mod);
                        PublicEncryptDecrypt(sequence_high, tempHost->pub_key, tempHost->mod);

                        //send accept encrypt communication message
                        int messLen = createAcceptEncryptCom(tcpSendBuffer, sequence_high, sequence_low);
                        tempHost->sendPacketToHost(tcpSendBuffer, messLen);
                    }
                } else{
                    printToConsole("Expected Establish Message.");
                }

                /*cout << tcpReadBuffer[0] << tcpReadBuffer[1] << tcpReadBuffer[2] << tcpReadBuffer[3] << endl;
                cout << "Type: " << ntohs(*(short*)(tcpReadBuffer+4)) << endl;
                cout << "Username: " << tcpReadBuffer+6 << endl;*/
                //cout << tcpReadBuffer+6;
            }
            else{ printToConsole("Max connections reached. Can't add another connection."); }
        }

        //CONSOLE file descriptor
        if(fds[2].revents && POLLIN){
            if(0 > read(STDIN_FILENO, appBuffer+(appBufferLen), 1)){
                error("Error reading in from stdin");
            }

            char curChar = *(appBuffer+appBufferLen);
            //printf("%02x\n", *(appBuffer+appBufferLen)&0xff);

            if(curChar == '\n'){
                *(appBuffer+appBufferLen) = '\0';
                write(STDOUT_FILENO, "\n", 1);
                
                if(appBufferLen != 0){
                    //pass into command parser
                    parseCommand(appBuffer);
                }

                if(directedHost != NULL){
                    sprintf(tempBuffer, "TX %s@%s> ", directedHost->username, directedHost->hostname);
                    write(STDOUT_FILENO, tempBuffer, strlen(tempBuffer));
                }

                appBufferLen = 0;
            } else if(curChar == 0x7f){ //backspace
                if(appBufferLen != 0){
                    appBufferLen--;
                    write(STDOUT_FILENO, "\b \b", 3);
                } else{ 
                    //write bell character to indicate invalid
                    curChar = 0x07;
                    write(STDOUT_FILENO, &curChar, 1); 
                }
            } else if(curChar == 0x1B){
                //throw away next character
                read(STDIN_FILENO, &curChar, 1);
                read(STDIN_FILENO, &curChar, 1);
                curChar = 0x7;
                write(STDOUT_FILENO, &curChar, 1);
            } else if(curChar > 31){
                write(STDOUT_FILENO, &curChar, 1);
                //printf("%c", *(appBuffer+appBufferLen));
                appBufferLen++;
            }
        }

        //Spawned Connections=======================================================================================
        for(int i = 0; i < tcpConnections; i++){
            if(fds[DEFAULT_FD_NUM+i].revents && POLLIN){
                Host* curHost = tcpHosts[fds[DEFAULT_FD_NUM+i].fd];

                if(0 > read(curHost->tcpFD, tcpReadBuffer, 6)){
                    error("Read failed inside tcp connections");
                } else{
                    //decode the type
                    short curType = ntohs(*(short*)(tcpReadBuffer+4));

                    if(curType == ENCRYPTED_DATA_CHUNK){
                        bool send = false;

                        if(curHost->receiver){ 
                            curHost->recv_sequence--;
                        } else{ curHost->recv_sequence++; }

                        //read in 64 bytes
                        if(0 > read(curHost->tcpFD, tcpReadBuffer, 64)){
                            error("Read failed inside tcp connections");
                        }

                        //decrypt the payload
                        PrivateEncryptDecrypt((uint8_t*)tcpReadBuffer, 64, curHost->recv_sequence);

                        uint16_t encType = ntohs(*(uint16_t*)(tcpReadBuffer));
                        //printf("Encrypted Type: %x\n", encType);
                        int packetLen;

                        if(encType == REQUEST_UL_ENCRYPT){
                            //printf("REQUEST_UL_ENCRYPT\n");
                            send = true;

                            //create payload
                            packetLen = createTCPUserListReply(tcpSendBuffer, myHosts.size(), true);
                            char* tempPtr = tcpSendBuffer + packetLen;
                            int tempLen = 0;
                            for(int i = 0; i < myHosts.size(); i++){
                                tempLen += createTCPUserListEntry(tempPtr+tempLen, i, myHosts[i]);
                            }

                            packetLen+=tempLen;
                            //curHost->sendPacketToHost(tcpSendBuffer, packetLen);
                        } else if(encType == USER_UNAVAIL_ENCRYPT){
                            curType = USER_UNAVAIBLABLE_TYPE;
                        } else if(encType == DISCONT_COM_ENCRYPT){
                            curType = DISCONTINUE_COM_TYPE;
                        } else if(encType == DATA_ENCRYPT) {
                            //printf("DATA_ENCRYPT\n");
                            bool endOfMessage = false;
                            int readLen = 64;

                            for(int i = 2; i < 64; i++){
                                if(tcpReadBuffer[i] == '\0'){
                                    endOfMessage = true;
                                }
                            }

                            while(!endOfMessage){
                                if(curHost->receiver){ 
                                    curHost->recv_sequence--;
                                } else{ curHost->recv_sequence++; }

                                //throw away data chunk header
                                if(0 > read(curHost->tcpFD, tempBuffer, 6)){
                                    error("Read failed inside tcp connections");
                                }

                                //read in payload
                                if(0 > read(curHost->tcpFD, tcpReadBuffer+readLen, 64)){
                                    error("Read failed inside tcp connections");
                                }

                                //decrypt the payload
                                PrivateEncryptDecrypt((uint8_t*)(tcpReadBuffer+readLen), 64, curHost->recv_sequence);
                                
                                for(int i = 0; i < 64; i++){
                                    if(tcpReadBuffer[i+readLen] == '\0'){
                                        endOfMessage = true;
                                    }
                                }

                                readLen+=64;
                            }

                            sprintf(tempBuffer, "RX %s@%s> %s", curHost->username, curHost->hostname, tcpReadBuffer+2);
                            printToConsole(tempBuffer);
                        } else if(encType == ESTABLISH_COM_ENCRYPT){
                            sprintf(tempBuffer, "Received establish communication inside Encrypted Data from %s@%s.", curHost->username, curHost->hostname);
                            printToConsole(tempBuffer);
                            send = true;
                            packetLen = createTCPPacket(tcpSendBuffer, ENCRYPTED_DATA_CHUNK, "");
                            curHost->sendDataChunkHeader(tcpSendBuffer, messLen);

                            //create payload for encrypted accept communication
                            *(uint16_t*)tcpSendBuffer = ntohs(ACCEPT_COM_ENCRYPT);
                            packetLen = 2;
                        } else if(encType == ACCEPT_COM_ENCRYPT){
                            sprintf(tempBuffer, "Received accept communication inside Encrypted Data inside %s@%s.", curHost->username, curHost->hostname);
                            printToConsole(tempBuffer);
                        } else if(encType == USER_LIST_REPLY_ENCRYPT){
                            sprintf(tempBuffer, "Received User List Reply");
                            printToConsole(tempBuffer);
                            //process user list reply
                            int totalHosts = ntohl(*(uint32_t*)(tcpReadBuffer+2));
                            int curCount = 0;
                            int validLen = 64;
                            int readLen = 6;
                            Host* insertHost;

                            while(curCount < totalHosts){
                                insertHost = new Host();
                                //entry number
                                if(validLen - readLen < 4){
                                    //read in next segment
                                    //throw away data chunk header
                                    curHost->recvDataChunkHeader();

                                    read(curHost->tcpFD, tcpReadBuffer+readLen, 64);
                                    PrivateEncryptDecrypt((uint8_t*)(tcpReadBuffer+readLen), 64, curHost->recv_sequence);
                                    validLen+=64;
                                }

                                //int entryNum = ntohs(*(uint16_t*)(tcpReadBuffer+readLen));
                                readLen+=4;

                                //UDP Port
                                if(validLen - readLen < 2){
                                    //read in next segment
                                    //throw away data chunk header
                                    curHost->recvDataChunkHeader();

                                    read(curHost->tcpFD, tcpReadBuffer+readLen, 64);
                                    PrivateEncryptDecrypt((uint8_t*)(tcpReadBuffer+readLen), 64, curHost->recv_sequence);
                                    validLen+=64;
                                }

                                //printf("UDP:%i ", tcpReadBuffer+readLen);
                                insertHost->udpPort = ntohs(*(uint16_t*)(tcpReadBuffer+readLen));
                                readLen+=2;

                                //Hostname
                                int j = readLen-1;
                                do{
                                    j++;
                                    
                                    if(validLen - j < 1){
                                        //read in next segment
                                        //throw away data chunk header
                                        curHost->recvDataChunkHeader();

                                        read(curHost->tcpFD, tcpReadBuffer+j, 64);
                                        PrivateEncryptDecrypt((uint8_t*)(tcpReadBuffer+j), 64, curHost->recv_sequence);
                                        validLen+=64;
                                    }
                                } while(tcpReadBuffer[j] != '\0');

                                //printf("Hostname:%s ", tcpReadBuffer+readLen);
                                insertHost->hostname = (char*)malloc(j+2-readLen);
                                strcpy(insertHost->hostname, tcpReadBuffer+readLen);
                                readLen = j+1;

                                //TCP Port
                                if(validLen - readLen < 2){
                                    //read in next segment
                                    //throw away data chunk header
                                    curHost->recvDataChunkHeader();

                                    read(curHost->tcpFD, tcpReadBuffer+readLen, 64);
                                    PrivateEncryptDecrypt((uint8_t*)(tcpReadBuffer+readLen), 64, curHost->recv_sequence);
                                    validLen+=64;
                                }

                                insertHost->tcpPort = ntohs(*(uint16_t*)(tcpReadBuffer+readLen));
                                readLen+=2;

                                //Username
                                j = readLen-1;
                                do{
                                    j++;
                                    
                                    if(validLen - j < 1){
                                        //read in next segment
                                        //throw away data chunk header
                                        curHost->recvDataChunkHeader();

                                        read(curHost->tcpFD, tcpReadBuffer+j, 64);
                                        PrivateEncryptDecrypt((uint8_t*)(tcpReadBuffer+j), 64, curHost->recv_sequence);
                                        validLen+=64;
                                    }
                                } while(tcpReadBuffer[j] != '\0');

                                //printf("Username:%s\n", tcpReadBuffer+readLen);
                                insertHost->username = (char*)malloc(j+2-readLen);
                                strcpy(insertHost->username, tcpReadBuffer+readLen);
                                readLen = j+1;

                                int messLen = fillUDPMessage(udpSendBuffer, DISCOVERY_TYPE, myUDPPort, myTCPPort, myHostname, myUsername);

                                Host myHostInfo(udpSendBuffer);

                                sprintf(tempBuffer, "User %i %s@%s UDP %i TCP %i", curCount, insertHost->username, insertHost->hostname, insertHost->udpPort, insertHost->tcpPort);
                                printToConsole(tempBuffer);

                                //filter out own host
                                if(!(*insertHost == myHostInfo) && !insertIntoHostVector(insertHost)){
                                    //cout << "found host in hostvector" << endl;
                                    delete insertHost;
                                }

                                curCount++;
                            }
                        } else if(encType == DUMMY){
                            //printToConsole("Dummy received.");
                        }

                        int headerLen;
                        if(send){
                            //send encrypted reply in fragments if greater than 64 bits
                            //pad the end
                            GenerateRandomString((uint8_t*)(tcpSendBuffer+packetLen), 64 - packetLen%64, curHost->send_sequence);
                            
                            int sentLen = 0;

                            while(sentLen < packetLen){
                                headerLen = createTCPPacket(tempBuffer, ENCRYPTED_DATA_CHUNK, "");
                                curHost->sendDataChunkHeader(tempBuffer, headerLen);
                                PrivateEncryptDecrypt((uint8_t*)(tcpSendBuffer+sentLen), 64, curHost->send_sequence);
                                curHost->sendPacketToHost(tcpSendBuffer+sentLen, 64);
                                sentLen+=64;
                            }
                        }
                    }

                    if(curType == USER_UNAVAIBLABLE_TYPE || curType == DISCONTINUE_COM_TYPE){
                        sprintf(tempBuffer, "Closing connection with %s@%s.", curHost->username, curHost->hostname);
                        printToConsole(tempBuffer);

                        //close connection, remove fd from fds, decrement tcp connections
                        if(curHost->closeConnection(&tcpConnections, i, fds, &tcpHosts)){
                            i--;

                            switch(curType){
                                case USER_UNAVAIBLABLE_TYPE:
                                    printToConsole("User Unavailable. Connection closed.");
                                case DISCONTINUE_COM_TYPE:
                                    printToConsole("Connection Discontinued. Connection closed.");
                            }

                            if(directedHost != NULL && *curHost == *directedHost){
                                directedHost = NULL;
                            }
                        }
                    } else if(curType == REQUEST_USER_LIST_TYPE){
                        //printToConsole("Request user list");;
                        //send user list reply message
                        int packetLen = createTCPUserListReply(tcpSendBuffer, myHosts.size(), false);
                        curHost->sendPacketToHost(tcpSendBuffer, packetLen);

                        //send the list entries
                        for(int i = 0; i < myHosts.size(); i++){
                            packetLen = createTCPUserListEntry(tcpSendBuffer, i, myHosts[i]);
                            curHost->sendPacketToHost(tcpSendBuffer, packetLen);
                        }
                    } else if(curType == USER_LIST_REPLY_TYPE){
                        //printToConsole("PROCESSING USER LIST REPLY");
                        processUserListReply(curHost);
                    } else if(curType == DATA_TYPE){
                        //print out contents to the console
                        int i = 0;
                        do{
                            if(0 > read(curHost->tcpFD, tcpReadBuffer+i, 1)){
                                cerr << "Error reading in from" << endl;
                            }
                        } while(tcpReadBuffer[i++] != '\0');

                        sprintf(tempBuffer, "RX %s@%s> %s", curHost->username, curHost->hostname, tcpReadBuffer);
                        printToConsole(tempBuffer);
                    } else if(curType == ACCEPT_CM_TYPE){
                        curHost->state = TCP_CONNECTED;
                        sprintf(tempBuffer, "Connected to %s@%s at TCP Port %i", curHost->username, curHost->hostname, curHost->tcpPort);
                        printToConsole(tempBuffer);
                    } else if(curType == ACCEPT_ENCRYPTED_COM) {
                        printToConsole("Encrypted connection established.");
                        //read in sequence numbers
                        if(read(curHost->tcpFD, tcpReadBuffer, 16) < 0){
                            error("Error on reading from socket");
                        }

                        //decrypt sequence number
                        uint64_t sequence_high, sequence_low;

                        sequence_high = ntohll(*(uint64_t*)tcpReadBuffer);
                        sequence_low = ntohll(*(uint64_t*)(tcpReadBuffer+8));

                        PublicEncryptDecrypt(sequence_low, myDecryptKey, myModulus);
                        PublicEncryptDecrypt(sequence_high, myDecryptKey, myModulus);

                        sequence_high <<= 32;

                        //update curHost's fields
                        curHost->state = TCP_CONNECTED;
                        curHost->encrypted = true;
                        curHost->receiver = true;
                        curHost->send_sequence = sequence_high + sequence_low;
                        curHost->recv_sequence = sequence_high + sequence_low;

                        //printf("Received sequence number: %llu\n", curHost->recv_sequence);
                    }
                }
            } 
        }
    }

    close(SocketFileDescriptor);
    return 0;
}
