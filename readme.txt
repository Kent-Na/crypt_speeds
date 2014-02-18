Setup
Git repositories of this project(crypt_speeds), Cryptia and PicoSHA2 must be on same directory.

Complite and execute

openSSL version
clang++ openssl_main.cpp -lssl -lcrypto -g -O3 -std=c++11
time ./a.out

cryptia version
clang++ okd_main.cpp  -g -O3 -std=c++11
time ./a.out
