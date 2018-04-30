/*************************************************************************
	> File Name: test.cpp
	> Author: 
	> Mail: 
	> Created Time: 二  5/ 1 01:08:50 2018
 ************************************************************************/

#include <iostream>
#include "rsa.hpp"

int main()  
{  
    using namespace openssl;
    string e = Tools::RsaPublicEncrypt("hello world", "./rsa_public.key");
    string be = Tools::Base64Encode(e.c_str(), false);
    cout<<be<<endl;
} 
