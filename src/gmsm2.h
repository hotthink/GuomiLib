//
//  gmsm2.h
//  gmssl
//
//  Created by 谭钦翰 on 2018/7/30.
//

#ifndef gmsm2_h
#define gmsm2_h

#include "sm2/sm2.h"
#include "gmsm3.h"

typedef unsigned char byte;
//Sm2 encryption result
struct SM2_Cypher {
    byte *cypher;
    int length;
    
    ~SM2_Cypher();
};

//Signature information, including the byte string and its length
struct SigInfo {
    byte Signature[256];
    unsigned int length;
    ~SigInfo();
};

//PublicKey, including curve parameter, x-y coordinates and their lengths
struct PublicKey {
    int Curve;
    byte X[32];
    byte Y[32];
    
    bool VerifySignature(SigInfo *sig, byte *msg, int msg_length);   //The verifying method
    SM2_Cypher *SM2_Encrypt(byte *msg, int msg_length);
    ~PublicKey();
};

//PrivateKey, including the corresponding public key and the private key
struct PrivateKey {
    PublicKey PubKey;
    byte Key[32];
    
    SigInfo* Sign(byte *msg, int msg_length);   //The signing method
    byte* SM2_Decrypt(SM2_Cypher *in);
    ~PrivateKey();
};


//Pre-processing the message
byte* SignHashSm3(PublicKey *pub_key, byte *msg, int msg_length);

//Getting a pair of keys on EC
PrivateKey* Guomi_KEY_generator();



#endif /* gmsm2_h */


