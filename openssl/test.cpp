/*************************************************************************
	> File Name: test.cpp
	> Author: 
	> Mail: 
	> Created Time: 二  5/ 1 01:08:50 2018
 ************************************************************************/

#include <iostream>
#include "rsa_proxy.hpp"

int main()  
{  
    using namespace openssl;
    RSAProxy rsa;
    rsa.LoadPublicKeyFromFile("./public_key.pem");
    string e = rsa.RsaPublicEncrypt("hello world");
    string be = rsa.Base64Encode(e.c_str(), false);
    cout<<be<<endl;
    cout<<"=====sign====="<<endl;
    string src = "name=123&password=456";
    rsa.LoadPrivateKeyFromFile("./private_key.pem");
    string sb = rsa.MakeSign(src);
    string sign = rsa.Base64Encode(sb.c_str(), false);
    cout<<sign<<endl;
    cout<<rsa.VerifySign(src, sign)<<endl;
} 
