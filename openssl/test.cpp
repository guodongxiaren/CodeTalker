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
} 
