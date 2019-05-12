#ifndef sm3_h
#define sm3_h
#include "sm3/sm3.h"

typedef unsigned char byte;

//SM3 hash function, receiving  the message and its length, returning the hash value
byte* sm3_hash(byte *msg, int length);

byte* sm3_hash2BER(byte *msg);

byte* sm3_hashBER_decode(byte *input);


#endif /* sm3_h */
