//
//  packetDriver.cpp
//  eternalblue_poc
//
//  Created by Zorik Cherfas on 06/08/2017.
//  Copyright © 2017 Zorik Cherfas. All rights reserved.
//

#include "packetDriver.hpp"


bool PacketDriver::createSocket(Protocol protocol){
    
    
    //Create socket
    int socketProtocol;
    
    switch (protocol) {
        case PROTOCOL_UDP:
            socketProtocol = SOCK_DGRAM;
            break;
        case PROTOCOL_TCP:
            socketProtocol = SOCK_STREAM;
            break;
            
        default:
            puts("Error , Protocol is not supporeted");
            break;
    }
    
    this->m_sock = socket(AF_INET , socketProtocol , 0);
    if (m_sock == -1)
    {
        printf("Could not create socket");
        return false;
    }
    puts("Socket created");
    
    printf("Setting ip address %s\n",m_ipAddress);
    m_server.sin_addr.s_addr = inet_addr(m_ipAddress);
    m_server.sin_family = AF_INET;
    m_server.sin_port = htons( m_port );
    
    return true;
}

bool PacketDriver::connectSocket(){
    
    //Connect to remote server
    if (connect(m_sock , (struct sockaddr *)&m_server , sizeof(m_server)) < 0)
    {
        perror("connect failed. Error");
        return false;
    }
    
    puts("Connected\n");
    return  true;
}

bool PacketDriver::communicateSocket(){
    
    //keep communicating with server
    while(1)
    {
        printf("Enter message : ");
        scanf("%s" , m_message);
        
        //Send some data
        if( send(m_sock , m_message , strlen(m_message) , 0) < 0)
        {
            puts("Send failed");
            return false;
        }
        
        //Receive a reply from the server
        if( recv(m_sock , m_server_reply , 2000 , 0) < 0)
        {
            puts("recv failed");
            break;
        }
        
        puts("Server reply :");
        puts(m_server_reply);
    }
    return true;
}

void PacketDriver::closeSocket(){
    
    if(m_sock){
        close(m_sock);
    }
    
}
