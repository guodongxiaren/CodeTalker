OPENSSL=/usr/local/ssl
DEBUG=./debug/
sign: rsa.hpp
	g++ test.cpp  -o $(DEBUG)/$@ -I $(OPENSSL)/include/ -L $(OPENSSL)/lib/ -lcrypto
