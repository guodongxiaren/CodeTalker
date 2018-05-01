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

    // load private key from file by filename
    void LoadPrivateKeyFromFile(const string& private_key_filename);
    
    // load public key from file by filename
    void LoadPublicKeyFromFile(const string& public_key_filename, 
                              PublicKeyFormat format = PublicKeyFormat::DEFAULT);

    // load public key from memory 
    void LoadPublicKeyFromMem(const string& public_key_string, 
                              PublicKeyFormat format = PublicKeyFormat::DEFAULT);

    string RsaPublicEncrypt(const string& plainText,
                                   PublicKeyFormat format = PublicKeyFormat::DEFAULT);
    
    string MakeSign(const string& src_string);

    bool VerifySign(const string& src_string, const string& sign);
    
public:
    static string Base64Encode(const string& input, bool with_new_line);
    static string Base64Decode(const string& input, bool with_new_line);
    static string Sha256(const char* data, bool bHex = true);

private:
    RSA* rsa_;
    RSA* pri_key_;
};

int pawd_callback(char* a, int b, int c, void* d)
{
    cout<<"ddd"<<endl;

    return 0;
}

// load private key from file by filename
void RSAProxy::LoadPrivateKeyFromFile(const string& private_key_filename)
{
    BIO *keybio = NULL;
    //// read public key from memory
    //keybio = BIO_new_mem_buf((unsigned char*)publicKey.c_str(), -1);

    // read public key from file system
    keybio = BIO_new(BIO_s_file());
    BIO_read_filename(keybio, private_key_filename.c_str());

    pri_key_ = PEM_read_bio_RSAPrivateKey(keybio, &pri_key_, (pem_password_cb*)pawd_callback, NULL);
    cout<<"private key address"<<pri_key_<<endl;
    
    BIO_free_all(keybio);
    
}
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

string RSAProxy::MakeSign(const string& sign_src)
{
    RSA* _rsa_ = pri_key_;
    string hash = Sha256(sign_src.c_str(), false);
    unsigned int outlen;
    unsigned char outret[4096] = {0};
    int result = RSA_sign(NID_sha1, (const unsigned char*)hash.c_str(), hash.size(), outret, &outlen, _rsa_);

    if(result != 1)
    {
        printf("sign error\n");
        //return -1;
        //throw xxx
    }
    return string((char*)outret, outlen);
}
bool RSAProxy::VerifySign(const string& src_string, const string& sign)
{
    RSA* pub_key_ = rsa_;
    if (NULL == pub_key_)
    {
        return false;
    }
    // 将原串经过sha256摘要(摘要算法根据实际使用来,此处以sha256为例)
    string hash = Sha256(src_string.c_str(), false);
    // 将待验证签名用base64解码(一般给的签名是经过base64编码的)
    string sign_bin = Base64Decode(sign, false);
    // 此处签名长度根据实际使用来,最好不要直接strlen(sign),可能发生截断
    int sign_len = sign_bin.size();
    int res = RSA_verify(NID_sha1, (const unsigned char*)hash.c_str(), hash.size(),
                         (unsigned char*)sign_bin.c_str(), sign_len, pub_key_);
    if (res == 1)
    {
        cout<<"signature verify ok"<<endl;
    }
    else
    {
        // 此api打印了验证失败的原因(bad signature,sigature length error等)
    }  
    return res == 1;    
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
    
string RSAProxy::Sha256(const char* data, bool bHex /* = true */)
{
    unsigned char md[SHA256_DIGEST_LENGTH] = {0};
    
    SHA256((const unsigned char *)data, strlen(data), md);
    if (!bHex)
    {
        string s;
        s.resize(SHA256_DIGEST_LENGTH);
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            s[i] = md[i];
        }
        return s;
    }
    else
    {
        string s;
        s.resize(SHA256_DIGEST_LENGTH * 2);
        int k = 0;
        for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH ; i++)
        {
            sprintf(&s.at(k), "%02x", md[i]);
            k += 2;
        }
        return s;
    }
}
} // namespace openssl
#endif
