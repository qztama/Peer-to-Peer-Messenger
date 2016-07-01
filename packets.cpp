#include "packets.h"

uint64_t ntohll(uint64_t val){
    if(ntohl(0xAAAA5555) == 0xAAAA5555){
        return val;
    }
    return (((uint64_t)ntohl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (ntohl((uint32_t)(val>>32)));
}

uint64_t htonll(uint64_t val){
    if(htonl(0xAAAA5555) == 0xAAAA5555){
        return val;
    }
    return (((uint64_t)htonl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (htonl((uint32_t)(val>>32)));
}

int createTCPPacket(char* packet, short type, const char* message){
    strcpy(packet, "P2PI");
    *(short*)(packet+4) = htons(type);

    if(type == DATA_TYPE || type == ESTABLISH_COM_TYPE || type == ESTABLISH_ENCRYPTED_COM){
        strcpy(packet+6, message);

        return (6 + strlen(message) + 1);
    }

    return 6;
}

int createEstablishEncryptCom(char* packet, char* username, uint64_t pub_key, uint64_t mod){
    int messLen = createTCPPacket(packet, ESTABLISH_ENCRYPTED_COM, username);
    *(uint64_t*)(packet+messLen) = htonll(pub_key);
    *(uint64_t*)(packet+messLen+8) = htonll(mod);

    return(messLen + 16);
}

int createAcceptEncryptCom(char* packet, uint64_t enc_sequence_high, uint64_t enc_sequence_low){
    int messLen = createTCPPacket(packet, ACCEPT_ENCRYPTED_COM, "");
    *(uint64_t*)(packet+messLen) = htonll(enc_sequence_high);
    messLen+=8;
    *(uint64_t*)(packet+messLen) = htonll(enc_sequence_low);
    messLen+=8;

    return messLen;
}

int createTCPUserListReply(char *packet, int myHostsSize, bool encrypted){
    int messLen = 0;
    if(!encrypted){
        strcpy(packet, "P2PI");
        *(short*)(packet+4) = htons(USER_LIST_REPLY_TYPE);
        messLen+=6;
    } else{
        *(short*)(packet) = htons(USER_LIST_REPLY_ENCRYPT);
        messLen+=2;
    }
    *(int*)(packet+messLen) = htonl(myHostsSize);
    messLen+=4;

    return messLen;
}

int createTCPUserListEntry(char *packet, int entryNum, Host* host){
    int packet_ptr = 0;

    //cout << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" << endl;
    *(int*)(packet + packet_ptr) = htonl(entryNum);
    //cout << "Entry List Num " << *(int*)(packet + packet_ptr) << endl;
    packet_ptr+=4;

    *(short*)(packet + packet_ptr) = htons(host->udpPort);
    //cout << "UDP Port Num " << *(short*)(packet + packet_ptr) << endl;
    packet_ptr+=2;

    strcpy(packet+packet_ptr, host->hostname);
    //cout << "Hostname " << packet+packet_ptr << endl;
    packet_ptr+=(strlen(host->hostname)+1);

    *(short*)(packet+packet_ptr) = htons(host->tcpPort);
    //cout << "TCP Port Num " << *(short*)(packet+packet_ptr) << endl;
    packet_ptr+=2;

    strcpy(packet+packet_ptr, host->username);
    //cout << "Username " << packet+packet_ptr << endl;
    packet_ptr+=(strlen(host->username)+1);

    //cout << ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" << endl;

    // for(int i = 0; i < packet_ptr; i++){
    //     printf("%02x ", packet[i]);
    // }

    return packet_ptr;
}

int createReqAuthKeyMess(char* packet, uint64_t secretNum, char* username){
    int messLen = 6;
    strcpy(packet, "P2PI");
    *(short*)(packet+4) = htons(REQ_AUTH_KEY_TYPE);

    //TODO: check for Little endianess
    // printf("1: %d\n", secretNum & 0xFFFFFFFF);
    // printf("2: %d\n", (unsigned int)htonl(secretNum >> 32));
    // *(uint32_t*)(packet+messLen) = htonl(secretNum >> 32);
    // messLen += 4;
    // *(uint32_t*)(packet+messLen) = htonl(secretNum & 0xFFFFFFFF);
    // messLen += 4;
    *(uint64_t*)(packet+messLen) = htonll(secretNum);
    messLen+=8;


    strcpy(packet+messLen, username);
    messLen+=(strlen(username) + 1);

    return messLen;
}

int fillUDPMessage(char* buffer, short type, short udpPort, short tcpPort, char* hostname, char* username){
    int messLen;

    strcpy(buffer, "P2PI");
    *(short*)(buffer+4) = htons(type);
    *(short*)(buffer+6) = htons(udpPort);
    *(short*)(buffer+8) = htons(tcpPort);

    messLen = 10;

    strcpy(buffer+messLen, hostname);
    messLen+=strlen(hostname)+1; //+1 for the null character

    strcpy(buffer+messLen, username);
    messLen+=strlen(username)+1;

    return messLen;
}