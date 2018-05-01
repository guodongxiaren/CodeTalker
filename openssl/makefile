OPENSSL=/usr/local/ssl
DEBUG=./debug/
CFLAG=-std=c++11 -g
sign: rsa_proxy.hpp
	g++ test.cpp $(CFLAG)  -o $(DEBUG)/$@ -I $(OPENSSL)/include/ -L $(OPENSSL)/lib/ -lcrypto

.PHONY:clean
clean:
	rm -f *.pem *.key *.gch
