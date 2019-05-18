//
//  BER.c
//  GuomiLib
//
//  Created by 谭钦翰 on 2019/5/12.
//  Copyright © 2019年 谭钦翰. All rights reserved.
//

#include "BER.h"
#include <math.h>

void get_len_field(int length, int n, byte* beginning)
{
    if(length <= 0)
        return;
    
    beginning[0] = (byte)n | 0x80;
    beginning[n] = (length & 0x7F);
    n--;
    length = length >> 7;
    while(length != 0 && n != 0)
    {
        beginning[n] = (length & 0x7F) | 0x80;
        n--;
        length = length >> 7;
    }
}

void get_length(int* length, byte* len_field)
{
    *length = 0;
    if((len_field[0] & 0x80) == 0)
    {
        *length = len_field[0];
    }
    else
    {
        int n = len_field[0] & 0x7F;
        int i;
        for(i = 1; i <= n; i++)
        {
            *length = (*length) << 7;
            *length += len_field[i] & 0x7F;
        }
    }
}

//Big endian
void Bytes_encode(byte* cypher, int length, byte** output)
{
    int i;
    int total_length;

    
    if(length <= 0)
        return;
    
    for(i = 31; i > 0; i--)
    {
        if(length >> i != 0)
            break;
    }
    
    if(i < 7)
    {
        total_length = 1 + 1 + length;
        *output = (byte*)malloc(sizeof(byte) * total_length);
        
        (*output)[0] = (byte)0x3;
        (*output)[1] = length & 0x7F;
        memcpy(*output+2, cypher, length);
    }
    else
    {
        int n = ceil((double)(i+1)/7);
        total_length = 1 + 1 + n + length;
        *output = (byte*)malloc(sizeof(byte) * total_length);
        
        (*output)[0] = (byte)0x3;
        get_len_field(length, n, *output+1);
        memcpy(*output + n + 2, cypher, length);
    }
}

void Bytes_decode(byte** cypher, int* length, byte* input)
{
    if((input[1] & 0x80) == 0)
    {
        *length = input[1] & 0x7F;
        *cypher = (byte*) malloc(*length * sizeof(byte));
        memcpy(*cypher, input + 2, *length);
    }
    else
    {
        get_length(length, input + 1);
        *cypher = (byte*) malloc(*length * sizeof(byte));
        memcpy(*cypher, input + 2 + (input[1] & 0x7F), *length);
    }
}


void SM2_PublicKey_encode(byte* X, byte* Y, byte** output)
{
    int total_length = 1 + 1 + 2 * (1 + 1 + 32);
    *output = (byte*)malloc(total_length * sizeof(byte));
    
    (*output)[0] = 0x30;
    (*output)[1] = 2 * (1 + 1 + 32);
    
    byte *temp = NULL;
    Bytes_encode(X, 32, &temp);
    memcpy(*output + 2, temp, 34);
    if(temp != NULL)
        free(temp);
    Bytes_encode(Y, 32, &temp);
    memcpy(*output + 36, temp, 34);
    if(temp != NULL)
        free(temp);
}

void SM2_PublicKey_decode(byte X[], byte Y[], byte* input)
{
    memcpy(X, input + 4, 32);
    memcpy(Y, input + 38, 32);
}


