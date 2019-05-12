//
//  gmsm4.cpp
//  gmssl
//
//  Created by 谭钦翰 on 2018/7/27.
//
#include<cstdlib>
#include<ctime>
#include<cstring>
#include "asn1/BER.h"
#include "gmsm4.h"
#include <iostream>
using namespace std;

//Here we only encode the cyher, because the iv shouldn't be directly transferred through network.
byte* Sm4CbcResult::BERencode()
{
    byte *output = NULL;
    Bytes_encode(this->cypher, this->length, &output);
    
    return output;
}

void Sm4CbcResult::BERdecode(byte *input)
{
    Bytes_decode(&(this->cypher), &(this->length), input);
}

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
    
        if((length & 0x0000000F) == 0)
        {
            output->cypher = new byte[length];
            sm4_crypt_cbc(&ks, 1, length, iv, src, output->cypher);
            output->length = length;
        }
        else
        {
            int padded_length = length + 16 - (length & 0x0000000F);
            byte *data = new byte[padded_length];
            memcpy(data, src, length);
            for(int i=0; i<16 - (length & 0x0000000F); i++){
                data[padded_length-1-i] = (byte)(16 - (length & 0x0000000F));
            }
            output->cypher = new byte[padded_length];
            sm4_crypt_cbc(&ks, 1, padded_length, iv, data, output->cypher);
            output->length = padded_length;
            
            delete[] data;
        }
        
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
        SM4_KEY ks;
        byte *result = new byte[EncInfo->length];
    
        SM4_set_key(key, &ks);
        sm4_crypt_cbc(&ks, 0, EncInfo->length, EncInfo->iv, EncInfo->cypher, result);
        
        int padding = (int)result[EncInfo->length-1];
        int flag = 0;
        for(int i=1;i<=padding;i++)
        {
            if((int)result[EncInfo->length - i]!=padding)
            {
                flag=1;
                break;
            }
        }
        
        if(flag==0)
        {
            byte *data = new byte[EncInfo->length - padding];
            memcpy(data, result, EncInfo->length - padding);
            delete[] result;
            return data;
        }
        else
        {
            return result;
        }

        }
    catch (exception e)
    {
        return NULL;
    }
}
