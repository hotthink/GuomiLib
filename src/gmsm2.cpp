
//  gmsm2.cpp
//  gmssl
//
//  Created by 谭钦翰 on 2018/7/30.
//

#include "gmsm2.h"
#include <string>
#include <iostream>
using namespace std;


byte AsciiToByte(byte b)
{
    byte res = 0;
    
    if(b >= '0' && b <= '9')
        res = b - '0';
    else if(b >= 'A' && b <= 'F')
        res = b - 'A' + 10;
    else if(b >= 'a' && b <= 'f')
        res = b - 'a' + 10;
    else
        res = 0;
    
    return res;
}

byte* SignHashSm3(PublicKey *pub_key, byte *msg, int msg_length){
    string ENTL1 = "00";
    string ENTL2 = "80";
    string userId = "31323334353637383132333435363738";
    string a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
    string b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
    string xG = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    string yG = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
    string tmp = ENTL1 + ENTL2 + userId + a + b + xG + yG;
    byte *content = new byte[(tmp.length() + 1)/2 + 64];
    byte *res = NULL;
    
    try{
    for(int i = 0; i < tmp.length(); i = i + 2)
    {
        if (i != tmp.length() - 1)
            content[i/2] = AsciiToByte(tmp[i]) * 16 + AsciiToByte(tmp[i + 1]);
        else
            content[i/2] = AsciiToByte(tmp[i]);
    }
    memcpy(content + (tmp.length() + 1)/2, pub_key->X, 32);
    memcpy(content + (tmp.length() + 1)/2 + 32, pub_key->Y, 32);
    
    res = sm3_hash(content, (tmp.length() + 1)/2 + 64);
    delete[] content;
    content = new byte[SM3_DIGEST_LENGTH + msg_length];
    memcpy(content, res, SM3_DIGEST_LENGTH);
    memcpy(content + SM3_DIGEST_LENGTH, msg, msg_length);
    byte *hashResult = sm3_hash(content, SM3_DIGEST_LENGTH + msg_length);

    delete[] res;
    delete[] content;
    return hashResult;
    }
    catch (exception e)
    {
        delete[] res;
        delete[] content;
        return NULL;
    }
    
}

byte* SM2_Cypher::BERencode()
{
    byte *output = NULL;
    Bytes_encode(this->cypher, this->length + ECC_BYTES * 2 + SM3_DIGEST_LENGTH, &output);
    
    return output;
}

void SM2_Cypher::BERdecode(byte *input)
{
    Bytes_decode(&(this->cypher), &(this->length), input);
    this->length -= ECC_BYTES * 2 + SM3_DIGEST_LENGTH;
}

SM2_Cypher::~SM2_Cypher(){
    if(this->cypher != NULL)
        delete[] this->cypher;
}

byte* SigInfo::BERencode()
{
    byte *output = NULL;
    Bytes_encode(this->Signature, this->length, &output);
    
    return output;
}

void SigInfo::BERdecode(byte *input)
{
    byte *temp = NULL;
    
    Bytes_decode(&(temp), &(this->length), input);
    memcpy(this->Signature, temp, this->length);
    
    if(temp != NULL)
        delete[] temp;
}

SigInfo* PrivateKey::Sign(byte *msg, int msg_length)
{
    SigInfo *sig = new SigInfo;
    sig->length = (unsigned int)(64);
    byte *dgst = SignHashSm3(&this->PubKey, msg, msg_length);
    int pid = sm2_sign(this->Key, dgst, sig->Signature);
    
    delete[] dgst;
    if(pid == 1)
        return sig;
    return NULL;
}

byte* PrivateKey::SM2_Decrypt(SM2_Cypher *in){
    byte *result = new byte[in->length];
    
    int temp = sm2_decrypt(this->Key, in->cypher, in->length, result);
    
    if(temp == 0){
        delete[] result;
        result = NULL;
    }
    
    return result;
}


bool PublicKey::VerifySignature(SigInfo *sig, byte *msg, int msg_length)
{
    try{
        byte *dgst = SignHashSm3(this, msg, msg_length);
        int result;
        
        result = sm2_verify(this->X, this->Y, dgst, sig->Signature);
        delete[] dgst;
        return result == 1;
    }
    catch (exception e)
    {
        return false;
    }
}

byte* PublicKey::BERencode()
{
    byte *output = NULL;
    SM2_PublicKey_encode(this->X, this->Y, &output);
    
    return output;
}

void PublicKey::BERdecode(byte *input)
{
    SM2_PublicKey_decode(this->X, this->Y, input);
}

SM2_Cypher* PublicKey::SM2_Encrypt(byte *msg, int msg_length){
    SM2_Cypher *result = new SM2_Cypher();
    
    result->cypher = new byte[msg_length + ECC_BYTES * 2 + SM3_DIGEST_LENGTH];
    result->length = msg_length;
    int temp = sm2_encrypt(this->X, this->Y, msg, msg_length, result->cypher);
    
    if(temp == 0){
        result = NULL;
    }
    
    return result;
}

PrivateKey* Guomi_KEY_generator(){

    try{
        PrivateKey *result = new PrivateKey;
        int pid = sm2_make_key(result->Key, result->PubKey.X, result->PubKey.Y);
        
        if(pid == 1)
            return result;
        else
            return NULL;
    }
    catch (exception e)
    {
        return NULL;
    }
}




