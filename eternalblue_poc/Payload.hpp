//
//  Payload.hpp
//  eternalblue_poc
//
//  Created by Zorik Cherfas on 06/08/2017.
//  Copyright © 2017 Zorik Cherfas. All rights reserved.
//

#ifndef Payload_hpp
#define Payload_hpp

#include <stdio.h>

class Payload{
    
public:
    
    int m_payloadSize;
    char* m_pPayload;
    
    void setPayloadSize(int size){
        m_payloadSize = size;
    }

    bool initPayload()
    {
        if(m_payloadSize == 0)
            return false;
        
        m_pPayload = new char[m_payloadSize];
        
        if(m_pPayload)
            return  true;
        else
            return false;
    }
    
    char *getPayloadPtr(){
        return m_pPayload;
    }
    int getPayloadLenght(){
        return m_payloadSize;
    }
    
    Payload(){
        m_payloadSize = 0;
        m_pPayload = 0;
    }
    ~Payload();
};
#endif /* Payload_hpp */
