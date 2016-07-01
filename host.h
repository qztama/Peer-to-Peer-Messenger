#ifndef HOST_H

#define HOST_H
#define TCP_NOT_CONNECTED	20
#define TCP_PENDING			21
#define TCP_CONNECTED		22
#define WAITING_FOR_ANCHOR  1
#define AUTH 				2
#define	NOT_IN_ANCHOR		3
#define UNAUTH				4
#include <netinet/in.h>
#include <iostream>
#include <stdio.h>
#include <netdb.h>
#include <poll.h>
#include <map>
     
#include <sys/types.h>
#include <string.h> 
#include <ifaddrs.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>

int GetLocalhostInformation(char *name, struct in_addr *addr, struct in_addr *mask);

class Host {
	public:
		char* hostname;
		char* username;
		int udpPort, tcpPort, tcpFD, state;
		uint64_t pub_key;
		uint64_t mod;
		uint64_t trust_pub_key;
		uint64_t trust_mod;
		uint64_t send_sequence;
		uint64_t recv_sequence;
		uint64_t secretNum;
		bool receiver;
		bool authenticated;
		bool auth_recvd;
		bool encrypted;
		char* buffer[1024];
		Host();
		Host(char*);
		~Host();
		Host(const Host &obj);
		bool operator==(const Host&);
		int TCPConnectToHost();
		void sendDataChunkHeader(char*, int);
		void recvDataChunkHeader();
		void sendPacketToHost(char*, int);
		bool closeConnection(int*, int, struct pollfd*, std::map<int, Host*>*);
		int checkAuthentication();
		void printHost(int);
		void debug();
};

#endif