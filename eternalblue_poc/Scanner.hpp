//
//  Scanner.hpp
//  eternalblue_poc
//
//  Created by Zorik Cherfas on 06/08/2017.
//  Copyright © 2017 Zorik Cherfas. All rights reserved.
//

#ifndef Scanner_hpp
#define Scanner_hpp

#include <stdio.h>



class Scaner{
    
    Scaner();
    ~Scaner();
    
    
    void startScan();
    void stopScan();
    void getResult();
};


#endif /* Scanner_hpp */
