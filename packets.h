#ifndef PACKETS_H
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include "host.h"

// #ifndef htonll
// uint64_t ntohll(uint64_t val){
//     if(ntohl(0xAAAA5555) == 0xAAAA5555){
//         return val;
//     }
//     return (((uint64_t)ntohl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (ntohl((uint32_t)(val>>32)));
// }

// uint64_t htonll(uint64_t val){
//     if(htonl(0xAAAA5555) == 0xAAAA5555){
//         return val;
//     }
//     return (((uint64_t)htonl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (htonl((uint32_t)(val>>32)));
// }
// #endif

#define DISCOVERY_TYPE          1
#define REPLY_TYPE              2
#define CLOSING_TYPE            3
#define ESTABLISH_COM_TYPE      4
#define ACCEPT_CM_TYPE          5
#define USER_UNAVAIBLABLE_TYPE  6
#define REQUEST_USER_LIST_TYPE  7
#define USER_LIST_REPLY_TYPE    8
#define DATA_TYPE               9
#define DISCONTINUE_COM_TYPE    10
#define ESTABLISH_ENCRYPTED_COM 0xB
#define ACCEPT_ENCRYPTED_COM	0xC
#define ENCRYPTED_DATA_CHUNK	0xD
#define REQ_AUTH_KEY_TYPE		0x10
#define REQ_AUTH_REPLY_TYPE		0x11
#define ESTABLISH_COM_ENCRYPT	0x5555
#define ACCEPT_COM_ENCRYPT		0xAAAA
#define USER_UNAVAIL_ENCRYPT	0xFF00
#define REQUEST_UL_ENCRYPT		0x00FF
#define USER_LIST_REPLY_ENCRYPT	0x5A5A
#define DATA_ENCRYPT			0xA5A5
#define DISCONT_COM_ENCRYPT		0xF0F0
#define DUMMY					0x0F0F

uint64_t ntohll(uint64_t val);
uint64_t htonll(uint64_t val);
int createTCPPacket(char* packet, short type, const char* message);
int createEstablishEncryptCom(char* packet, char* username, uint64_t pub_key, uint64_t mod);
int createAcceptEncryptCom(char* packet, uint64_t enc_sequence_high, uint64_t enc_sequence_low);
int createTCPUserListReply(char *packet, int myHostsSize, bool encrypted);
int createTCPUserListEntry(char *packet, int entryNum, Host* host);
int createReqAuthKeyMess(char* packet, uint64_t secretNum, char* username);
int fillUDPMessage(char* buffer, short type, short udpPort, short tcpPort, char* hostname, char* username);
#endif