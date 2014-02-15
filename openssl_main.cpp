#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <stdint.h>

//Compile this with
//clang openssl_main.cpp -lssl -lcrypto -std=c++11 -g -O3

int main(int argc, char** argv){

	//Simple crypt function speed tests.	

	//Routine are,
	//1, Generate 512 byte random data "A".
	//2, Hash it with SHA2.
	//3, Encrypt "A" with RSA and cal it "B".
	//4, Decrypt "B"

	constexpr size_t data_length = 64;
	constexpr size_t sample_size = 10000;

	printf("Data size = %zu, Samule size = %zu\n",
			data_length, sample_size);

	//setup openSSL
	RAND_METHOD* method = RAND_SSLeay();
	RAND_set_rand_method(method);
	
	int r_val;
	SHA256_CTX sha256;
	FILE *f = fopen("testkey.pem","r");
	RSA* rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);

	const size_t encrypt_data_length = RSA_size(rsa);

	uint8_t raw_data[data_length];
	uint8_t encrypt[encrypt_data_length];
	uint8_t decrypt[data_length];
	uint8_t raw_data_hash[SHA256_DIGEST_LENGTH];
	uint8_t result_data_hash[SHA256_DIGEST_LENGTH];

	for (int i= 0; i<sample_size; i++){
		//Rand
		r_val = RAND_bytes(raw_data, data_length);

		//Hash
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, raw_data, data_length);
		SHA256_Final(raw_data_hash, &sha256);

		//Encrypt
		r_val = RSA_public_encrypt(
				data_length, raw_data, encrypt, 
				rsa, RSA_PKCS1_OAEP_PADDING);

		r_val = RSA_private_decrypt(
				encrypt_data_length, encrypt, decrypt, 
				rsa, RSA_PKCS1_OAEP_PADDING);
		
		//Hash
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, decrypt, data_length);
		SHA256_Final(result_data_hash, &sha256);

		for (int i = 0; i<SHA256_DIGEST_LENGTH; i++){
			if (raw_data_hash[i] != result_data_hash[i]){
				return 0;
			}
		}
	}

	printf("Compleate openSSL\n");

	return 0;	
}
