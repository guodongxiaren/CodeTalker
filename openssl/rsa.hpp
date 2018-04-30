/*************************************************************************
	> File Name: 
	> Author: 
	> Mail: 
	> Created Time: 日  4/29 23:05:55 2018
 ************************************************************************/
#ifndef _OPENSS_RSA_
#define _OPENSS_RSA_

#include<iostream>
#include<string>
using namespace std;

#include <stdio.h>  
#include <string.h>  
#include <stdlib.h>  
#include <openssl/bn.h>  
#include <openssl/rsa.h>  
#include <openssl/pem.h>  
  
namespace openssl{

class Tools 
{
public:
    static string RsaPublicEncrypt(const string& plainText, const string& publicKey);
    static string Base64Encode(const string& input, bool with_new_line);
    static string Base64Decode(const string& input, bool with_new_line);
        
};

string Tools::RsaPublicEncrypt(const string& plainText, const string& publicKey)
{
    string strRet;
    RSA *rsa = NULL;

    BIO *keybio = NULL;
    //// read public key from memory
    //keybio = BIO_new_mem_buf((unsigned char*)publicKey.c_str(), -1);

    // read public key from file system
    keybio = BIO_new(BIO_s_file());
    BIO_read_filename(keybio, publicKey.c_str());

    /* RSA *pRsaPublicKey = RSA_new(); */
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    //rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

    // initialize
    int len = RSA_size(rsa);
    char *encryptText = (char*)malloc(len + 1);
    memset(encryptText, 0, len + 1);
    
    int ret = RSA_public_encrypt(plainText.length(), (const unsigned char*)plainText.c_str(), 
                                (unsigned char*)encryptText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
    {
        strRet = string(encryptText, ret);
    }
    free(encryptText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;

}

string Tools::Base64Encode(const string& input, bool with_new_line)  
{  
    int length = input.size();
    BIO * bmem = NULL;  
    BIO * b64 = NULL;  
    BUF_MEM * bptr = NULL;  
  
    b64 = BIO_new(BIO_f_base64());  
    if(!with_new_line) {  
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
    }  
    bmem = BIO_new(BIO_s_mem());  
    b64 = BIO_push(b64, bmem);  
    BIO_write(b64, input.c_str(), length);  
    BIO_flush(b64);  
    BIO_get_mem_ptr(b64, &bptr);  
  
    char* buff = (char *)malloc(bptr->length + 1);  
    memcpy(buff, bptr->data, bptr->length);  
    buff[bptr->length] = 0;  
    string res(buff);
    free(buff);
  
    BIO_free_all(b64);  
  
    return res;  
}  
  
string Tools::Base64Decode(const string& input, bool with_new_line)  
{  
    int length = input.size();
    BIO * b64 = NULL;  
    BIO * bmem = NULL;  
    char * buffer = (char *)malloc(length);  
    memset(buffer, 0, length);  
  
    b64 = BIO_new(BIO_f_base64());  
    if(!with_new_line) {  
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
    }  
    bmem = BIO_new_mem_buf(input.c_str(), length);  
    bmem = BIO_push(b64, bmem);  
    BIO_read(bmem, buffer, length);  
    string res(buffer);
    free(buffer);
  
    BIO_free_all(bmem);  
  
    return res;  
}  

} // namespace openssl
#endif
