//
//  main.cpp
//  eternalblue_poc
//
//  Created by Zorik Cherfas on 06/08/2017.
//  Copyright © 2017 Zorik Cherfas. All rights reserved.
//

#define WINDOWS_7_BRIDGE "192.168.56.101"

#include <iostream>
#include "packetDriver.hpp"
int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";
    

    PacketDriver *pPacketDriver = new PacketDriver();
    pPacketDriver->setDestPort(445);
//    pPacketDriver->setIpAddress("10.0.2.15");
    pPacketDriver->setIpAddress((char*)WINDOWS_7_BRIDGE);

    pPacketDriver->createSocket(Protocol::PROTOCOL_TCP);
    
    
//    pPacketDriver->communicateSocket();
    pPacketDriver->stateMachine();
    
    
    
    
    return 0;
}
