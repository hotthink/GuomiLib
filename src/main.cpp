//
//  main.c
//  GuomiLib
//
//  Created by 谭钦翰 on 2018/10/8.
//  Copyright © 2018年 谭钦翰. All rights reserved.
//

#include <iostream>
#include "gmsm2.h"
#include "gmsm3.h"
#include "gmsm4.h"
using namespace std;

int main(int argc, const char * argv[]) {
    PrivateKey *pri_key = Guomi_KEY_generator();
    SM2_Cypher *SM2_encrypt_result = pri_key->PubKey.SM2_Encrypt((byte*)"1234567890", 10);
    
    if(SM2_encrypt_result != NULL)
        cout << pri_key->SM2_Decrypt(SM2_encrypt_result) << endl;
//    SigInfo *sig = pri_key->Sign((byte*)"1234567890", 10);
//
//    cout << pri_key->PubKey.VerifySignature(sig, (byte*)"1234567890", 10) << endl;
//
//    cout << sm3_hash((byte*)"123456", 6) << endl;
//
//    byte *key = (byte*)"1234567890123456";
//    byte *plain = (byte*)"12345678901234567890";
//    Sm4CbcResult *result = Sm4EncCBCIV(key, plain, 20);
//    cout << Sm4DecCBCIV(key, result) << endl;
//    test1();
    return 0;
}
