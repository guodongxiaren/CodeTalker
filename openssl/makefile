OPENSSL=/usr/local/ssl
DEBUG=./debug/
CFLAG=-std=c++11
sign: rsa.hpp
	g++ test.cpp $(CFLAG)  -o $(DEBUG)/$@ -I $(OPENSSL)/include/ -L $(OPENSSL)/lib/ -lcrypto
