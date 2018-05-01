/*************************************************************************
	> File Name: 
	> Author: guodongxiaren 
	> Mail: 
	> Created Time: 日  4/29 23:05:55 2018
 ************************************************************************/
#ifndef _OPENSSL_RSA_
#define _OPENSSL_RSA_

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

enum PublicKeyFormat
{
    DEFAULT = 0,
    PKCS1 = 1,
    
};
class RSAProxy
{
public:
    RSAProxy()
    {
        rsa_ = NULL;
    }
    ~RSAProxy()
    {
        if (!rsa_)
        {
            RSA_free(rsa_);
            rsa_ = NULL;
        }
        // avoid memory leak
        CRYPTO_cleanup_all_ex_data();
    }

    RSA* data()
    {
        return rsa_;
    }

    int size()
    {
        return RSA_size(rsa_);
    }

    // load public key from file by filename
    void LoadPublicKeyFromFile(const string& public_key_filename, 
                              PublicKeyFormat format = PublicKeyFormat::DEFAULT);

    // load public key from memory 
    void LoadPublicKeyFromMem(const string& public_key_string, 
                              PublicKeyFormat format = PublicKeyFormat::DEFAULT);

    string RsaPublicEncrypt(const string& plainText,
                                   PublicKeyFormat format = PublicKeyFormat::DEFAULT);
public:
    static string Base64Encode(const string& input, bool with_new_line);
    static string Base64Decode(const string& input, bool with_new_line);

private:
    RSA* rsa_;
};


void RSAProxy::LoadPublicKeyFromFile(const string& public_key_filename, 
                                     PublicKeyFormat format /* = PublicKeyFormat::DEFAULT */)
{
    BIO *keybio = NULL;
    //// read public key from memory
    //keybio = BIO_new_mem_buf((unsigned char*)publicKey.c_str(), -1);

    // read public key from file system
    keybio = BIO_new(BIO_s_file());
    BIO_read_filename(keybio, public_key_filename.c_str());

    if (format == PublicKeyFormat::DEFAULT)
    {
        rsa_ = PEM_read_bio_RSA_PUBKEY(keybio, &rsa_, NULL, NULL);
    }
    else /* PKCS#1 */
    {
        rsa_ = PEM_read_bio_RSAPublicKey(keybio, &rsa_, NULL, NULL);
    }
    
    BIO_free_all(keybio);
}

string RSAProxy::RsaPublicEncrypt(const string& plainText, 
                               PublicKeyFormat format /* = PublicKeyFormat::DEFAULT */)
{
    if (rsa_ == NULL)
    {
        // throw xxx
    }

    int len = this->size();
    char *encrypt_text = (char*)malloc(len + 1);
    memset(encrypt_text, 0, len + 1);
    
    int ret = RSA_public_encrypt(plainText.length(), (const unsigned char*)plainText.c_str(), 
                                (unsigned char*)encrypt_text, rsa_, RSA_PKCS1_PADDING);
    string str_encrypt;
    if (ret >= 0)
    {
        str_encrypt = string(encrypt_text, ret);
        free(encrypt_text);
    }
    else
    {
        free(encrypt_text);
        // throw xxx
    }

    return str_encrypt;

}

string RSAProxy::Base64Encode(const string& input, bool with_new_line)  
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
  
string RSAProxy::Base64Decode(const string& input, bool with_new_line)  
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
