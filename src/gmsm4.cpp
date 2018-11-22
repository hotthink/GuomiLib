//
//  gmsm4.cpp
//  gmssl
//
//  Created by 谭钦翰 on 2018/7/27.
//
#include<cstdlib>
#include<ctime>
#include<cstring>
#include "gmsm4.h"
#include <iostream>
using namespace std;

Sm4CbcResult::~Sm4CbcResult()
{
    if (this->cypher != NULL)
        delete[] this->cypher;
}

void randomIV(byte iv[16])
{
    
    srand((unsigned)time(NULL));
    for(int i = 0; i < 16; i++)
    {
        iv[i] = byte(rand() % 256);
    }
}

Sm4CbcResult* Sm4EncCBCIV(byte *key, byte *src, int length)
{
    try{
        if(length < 16)
            return NULL;
        Sm4CbcResult *output = new Sm4CbcResult;
        byte iv[16];
        SM4_KEY ks;

        randomIV(iv);
        memcpy(output->iv, iv, 16);
        SM4_set_key(key, &ks);
        output->cypher = new byte[length];
        sm4_crypt_cbc(&ks, 1, length, iv, src, output->cypher);
        output->length = length;
    
        return output;
    }
    catch (exception e)
    {
        return NULL;
    }
}

byte* Sm4DecCBCIV(byte *key, Sm4CbcResult *EncInfo)
{
    try{
    if(EncInfo->length < 16)
        return NULL;
    SM4_KEY ks;
    byte *output = new byte[EncInfo->length];
    
    SM4_set_key(key, &ks);
    sm4_crypt_cbc(&ks, 0, EncInfo->length, EncInfo->iv, EncInfo->cypher, output);
    
    return output;
    }
    catch (exception e)
    {
        return NULL;
    }
}
