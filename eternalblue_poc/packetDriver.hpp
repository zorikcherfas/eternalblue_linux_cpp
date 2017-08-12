//
//  packetDriver.hpp
//  eternalblue_poc
//
//  Created by Zorik Cherfas on 06/08/2017.
//  Copyright © 2017 Zorik Cherfas. All rights reserved.
//

#ifndef packetDriver_hpp
#define packetDriver_hpp

#include <stdio.h>
#include<string.h>    //strlen
#include<stdlib.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include<pthread.h> //for threading , link with lpthread
#include "smbHeader.hpp"
enum Protocol{
    PROTOCOL_NONE,
    PROTOCOL_UDP,
    PROTOCOL_TCP,
    PROTOCOL_MAX
};
class PacketDriver{
    
    int m_port;
    int m_sock;
    SMB *m_smbConnectionHandler;
    Protocol m_protocol;
    char m_ipAddress[INET_ADDRSTRLEN];
    struct sockaddr_in m_server;
    char m_message[1000] , m_server_reply[2000];
    
public:
    PacketDriver(){
        /* Setting deafults */
        memset(m_ipAddress, 0, sizeof(INET_ADDRSTRLEN));
        m_port = 0;
        m_protocol = Protocol::PROTOCOL_NONE;
    }
    ~PacketDriver();
    
    void setDestPort( int port){
        m_port = port;
    }
    void setIpAddress(char *ipAddress){
        memcpy(m_ipAddress, ipAddress, strlen(ipAddress));
    }
    
    bool createSocket(Protocol protocol);
    bool connectSocket();
    bool communicateSocket();
    void closeSocket();
    bool stateMachine();
    void updateConnectionStateToNewState();
    
};

#endif /* packetDriver_hpp */
