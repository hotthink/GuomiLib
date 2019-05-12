#include "gmsm3.h"
#include "asn1/BER.h"
#include <iostream>
using namespace std;


byte* sm3_hash(byte *msg, int length)
{
    try{
        byte *dgst = new unsigned char[SM3_DIGEST_LENGTH];
        sm3_hash(msg, dgst, length);
    
        return dgst;
    }
    catch (exception e)
    {
        return NULL;
    }
}

byte* sm3_hash2BER(byte *dgst)
{
    byte *output = NULL;
    Bytes_encode(dgst, SM3_DIGEST_LENGTH, &output);
    
    return output;
}

byte* sm3_hashBER_decode(byte *input)
{
    byte *output = NULL;
    int length = 0;
    Bytes_decode(&output, &length, input);
    
    return output;
}
