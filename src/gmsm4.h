//
//  gmsm4.h
//  gmssl
//
//  Created by 谭钦翰 on 2018/7/27.
//

#ifndef gmsm4_h
#define gmsm4_h
#include "sm4/sm4.h"

typedef unsigned char byte;

//The encryption result, including the cypher text, its length and the random vector
struct Sm4CbcResult
{
    byte *cypher;
    int length;
    int plain_length;
    byte iv[16];
    
    byte* BERencode();
    void BERdecode(byte* input);
    ~Sm4CbcResult();
};

//Generating a 16-byte random vector
byte* randomIV();

//SM4 encryption function, CBC mode
Sm4CbcResult* Sm4EncCBCIV(byte *key, byte *src, int length);

//SM4 decryption function, CBC mode
byte* Sm4DecCBCIV(byte *key, Sm4CbcResult *EncInfo);


#endif /* gmsm4_h */
