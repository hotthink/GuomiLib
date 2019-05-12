//
//  BER.h
//  GuomiLib
//
//  Created by 谭钦翰 on 2019/5/12.
//  Copyright © 2019年 谭钦翰. All rights reserved.
//

#ifndef BER_h
#define BER_h
#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include "../gmsm2.h"
//#include "../gmsm3.h"
//#include "../gmsm4.h"
typedef unsigned char byte;

    
void Bytes_encode(byte* cypher, int length, byte** output);
void Bytes_decode(byte** cypher, int* length, byte* input);

void SM2_PublicKey_encode(byte X[], byte Y[], byte** output);
void SM2_PublicKey_decode(byte X[], byte Y[], byte* input);


#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* BER_h */
