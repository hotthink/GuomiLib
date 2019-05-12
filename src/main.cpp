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
//    SM2_Cypher *SM2_encrypt_result = pri_key->PubKey.SM2_Encrypt((byte*)"1234567890123456789012345678901234567890", 40);
//
//    byte *BER = SM2_encrypt_result->BERencode();
//    SM2_Cypher *temp = new SM2_Cypher;
//    temp->BERdecode(BER);
//
//    if(temp != NULL)
//        cout << pri_key->SM2_Decrypt(temp) << endl;
    
//    SigInfo *sig = pri_key->Sign((byte*)"1234567890", 10);
//    byte *sig_BER = sig->BERencode();
//
//    SigInfo *temp = new SigInfo;
//    temp->BERdecode(sig_BER);
//    PublicKey *pub_temp = new PublicKey;
//    pub_temp->BERdecode(pri_key->PubKey.BERencode());
//
//    cout << pub_temp->VerifySignature(temp, (byte*)"1234567890", 10) << endl;
//
//    cout << sm3_hash((byte*)"123456", 6) << endl;
//    cout << sm3_hashBER_decode(sm3_hash2BER(sm3_hash((byte*)"123456", 6))) << endl;

    
//
    byte *key = (byte*)"1234567890123456";
    byte *plain = (byte*)"12345678901234567890";
    Sm4CbcResult *result = Sm4EncCBCIV(key, plain, 20);
    
    Sm4CbcResult *SM4_BER = new Sm4CbcResult;
    memcpy(SM4_BER->iv, result->iv, 20);
    SM4_BER->BERdecode(result->BERencode());
    cout << Sm4DecCBCIV(key, SM4_BER) << endl;
    
//    test1();
    return 0;
}
