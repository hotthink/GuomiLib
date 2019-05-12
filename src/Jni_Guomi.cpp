#include "jni.h"
#include "Jni_Guomi.h"
#include "gmsm2.h"
#include "gmsm3.h"
#include "gmsm4.h"
#include <iostream>
#include <string.h>
using namespace std;
/* Header for class Jni_Guomi */

JNIEXPORT void JNICALL Java_GuomiJava_Jni_1Guomi_sm2GenerateKey
(JNIEnv *env, jobject obj, jbyteArray Pub_X, jbyteArray Pub_Y, jbyteArray Pri_Key)
{
    PrivateKey *pri_key = Guomi_KEY_generator();
    
    env->SetByteArrayRegion(Pub_X, 0, 32, (jbyte*)(pri_key->PubKey.X));
    env->SetByteArrayRegion(Pub_Y, 0, 32, (jbyte*)(pri_key->PubKey.Y));
    env->SetByteArrayRegion(Pri_Key, 0, 32, (jbyte*)(pri_key->Key));
    
}

JNIEXPORT jbyteArray JNICALL Java_GuomiJava_Jni_1Guomi_sm2Sign (JNIEnv *env, jobject obj, jbyteArray Pub_X,
                                                jbyteArray Pub_Y, jbyteArray Pri_Key, jbyteArray msg, jint msg_length)
{
    PrivateKey *pri_key = new PrivateKey;
    memcpy(pri_key->Key, (byte*)(env->GetByteArrayElements(Pri_Key, 0)), 32);
    memcpy(pri_key->PubKey.X, (byte*)(env->GetByteArrayElements(Pub_X, 0)), 32);
    memcpy(pri_key->PubKey.Y, (byte*)(env->GetByteArrayElements(Pub_Y, 0)), 32);

    
    SigInfo *sig_info = pri_key->Sign((byte*)(env->GetByteArrayElements(msg, 0)), msg_length);
    jbyteArray result = env->NewByteArray(sig_info->length);
    env->SetByteArrayRegion(result, 0, sig_info->length, (jbyte*)(sig_info->Signature));
 
    return result;
}

JNIEXPORT jboolean JNICALL Java_GuomiJava_Jni_1Guomi_sm2Verify (JNIEnv *env, jobject obj, jbyteArray Pub_X,
                                    jbyteArray Pub_Y, jbyteArray msg, jint msg_length, jbyteArray sig, jint sig_length)
{
    PublicKey *pub_key = new PublicKey;
    memcpy(pub_key->X, (byte*)(env->GetByteArrayElements(Pub_X, 0)), 32);
    memcpy(pub_key->Y, (byte*)(env->GetByteArrayElements(Pub_X, 0)), 32);
    
    SigInfo *sig_info = new SigInfo;
    memcpy(sig_info->Signature, (byte*)(env->GetByteArrayElements(sig, 0)), 256);
    
    bool result = pub_key->VerifySignature(sig_info, (byte*)(env->GetByteArrayElements(msg, 0)), msg_length);
    
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_GuomiJava_Jni_1Guomi_sm3Hash(JNIEnv *env, jobject obj, jbyteArray msg, jint length)
{
    jbyteArray result = env->NewByteArray(SM3_DIGEST_LENGTH);

    env->SetByteArrayRegion(result, 0, SM3_DIGEST_LENGTH, (jbyte*)(sm3_hash((byte*)(msg), length)));
    return result;
    //return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_GuomiJava_Jni_1Guomi_sm4CBCEnc(JNIEnv *env, jobject obj, jbyteArray msg,
                                                                 jint msg_length, jbyteArray key, jbyteArray iv)
{
    Sm4CbcResult *result = Sm4EncCBCIV((byte*)(env->GetByteArrayElements(key, 0)), (byte*)(env->GetByteArrayElements(msg, 0)), msg_length);
    jbyteArray cypher = env->NewByteArray(msg_length);
    
    env->SetByteArrayRegion(iv, 0, 16, (jbyte*)(result->iv));
    
    env->SetByteArrayRegion(cypher, 0, msg_length, (jbyte*)(result->cypher));
    
    result->~Sm4CbcResult();
    return cypher;
}

JNIEXPORT jbyteArray JNICALL Java_GuomiJava_Jni_1Guomi_sm4CBCDec(JNIEnv *env, jobject obj, jbyteArray cypher,
                                                                jint cypher_length, jbyteArray key, jbyteArray iv)
{
    Sm4CbcResult *EncInfo = new Sm4CbcResult;
    EncInfo->cypher = (byte*)(env->GetByteArrayElements(cypher, 0));
    memcpy(EncInfo->iv, (byte*)(env->GetByteArrayElements(iv, 0)), 16);
    EncInfo->length = cypher_length;
    
    byte *plain_txt = Sm4DecCBCIV((byte*)(env->GetByteArrayElements(key, 0)), EncInfo);
    jbyteArray output = env->NewByteArray(cypher_length);
    env->SetByteArrayRegion(output, 0, cypher_length, (jbyte*)plain_txt);
    EncInfo->~Sm4CbcResult();
    
    return output;
}

