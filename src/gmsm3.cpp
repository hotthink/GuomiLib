#include "gmsm3.h"
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
