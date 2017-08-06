//
//  Frame.hpp
//  eternalblue_poc
//
//  Created by Zorik Cherfas on 06/08/2017.
//  Copyright © 2017 Zorik Cherfas. All rights reserved.
//

#ifndef Frame_hpp
#define Frame_hpp

#include <stdio.h>

struct frame_struct {
    char* l2;
    char *l4;
    char *l7;
    
} ;
class Frame{
    
    Frame *frame;
    
    
public:
    Frame();
    ~Frame();
    
    void getProtocol();
    void getIpDest();
    void getIpSource();
};


#endif /* Frame_hpp */
