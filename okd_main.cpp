#include "../PicoSHA2/picosha2.h"
#include "../Cryptia/Cryptia.h"

const char* modulus = 
	"00:"
	"00:ae:7a:39:09:f9:4b:09:a9:2a:ce:2e:99:fb:a0:"
	"f2:8f:a9:f8:5b:72:ec:a1:f6:1c:7c:ea:ac:1b:8c:"
	"bb:76:04:7f:76:df:87:d6:22:15:49:1e:aa:bc:b9:"
	"c9:34:af:66:c8:27:e9:5c:16:ee:fd:b5:91:bb:2f:"
	"f5:3d:b3:23:6b:ff:80:c3:6f:46:96:06:39:a0:59:"
	"50:d7:46:05:a6:1e:e9:7f:63:e8:90:3f:97:5d:f3:"
	"4c:c7:ab:3c:08:88:0e:63:6c:15:36:f8:a8:6f:ee:"
	"6f:ec:ae:d9:94:9d:d2:57:56:64:29:8a:ab:7a:2a:"
	"e6:aa:67:11:bf:c5:97:2b:31";

const char* public_exponent = "00:""01:00:01";

const char* private_exponent = 
	"51:0f:97:d0:7a:71:d2:5b:35:f7:f4:ce:b5:89:61:"
	"28:3d:df:95:1d:1f:b3:5f:94:7c:b4:ca:a1:42:11:"
	"16:13:a0:e4:a9:95:82:76:f3:4c:b5:62:bd:ab:d3:"
	"3f:16:fe:b9:9f:51:5b:e7:8b:c1:73:c9:f1:1d:a6:"
	"e2:b3:87:90:b1:01:4f:f6:2a:a3:47:93:51:20:a5:"
	"db:80:3d:99:a6:06:b3:dd:9d:3a:ae:44:bd:ce:83:"
	"1d:f8:09:f9:c3:21:1e:aa:3d:a7:7f:03:e9:e5:43:"
	"85:27:0a:ab:f9:c9:57:77:18:11:aa:42:50:97:3d:"
	"5a:91:07:3f:e5:33:fc:c1";

auto str_to_vector(const char* str) -> cryptia::ByteArray{
	using namespace cryptia;
	auto itr = str;
	ByteArray out;

	auto hex_to_num = [](char hex){
		switch (hex){
			case '0': return 0;
			case '1': return 1;
			case '2': return 2;
			case '3': return 3;

			case '4': return 4;
			case '5': return 5;
			case '6': return 6;
			case '7': return 7;

			case '8': return 8;
			case '9': return 9;
			case 'a': return 10;
			case 'b': return 11;
				   
			case 'c': return 12;
			case 'd': return 13;
			case 'e': return 14;
			case 'f': return 15;
			default : return 0;
		}
	};

	while (*itr != '\0'){
		if (*itr == ':'){
			itr++;
		}
		uint8_t value = 0;
		value  = hex_to_num(*itr++)<<4;
		value |= hex_to_num(*itr++);

		out.push_back(value);
	}

	for (int i= 0; i<out.size(); i++){
		printf("%x:",out[i]);
	}
	printf("\n");

	return out;
}

int main(int argc, char** argv){
	using namespace cryptia;
	using namespace cryptia::random;
	using namespace cryptia::asymmetric_key;
	
	//Simple crypt function speed tests.	

	//Routine are,
	//1, Generate 512 byte random data "A".
	//2, Hash it with SHA2.
	//3, Encrypt "A" with RSA and cal it "B".
	//4, Decrypt "B"

	constexpr size_t data_length = 64;
	constexpr size_t sample_size = 10000;

	auto random = CkcRandom::Create(common_key::Aes::Create());
	random->Initialize(ByteArray(48, 1));

	printf("Data size = %zu, Samule size = %zu\n",
			data_length, sample_size);

	auto key_modulus = str_to_vector(modulus);
	auto key_public_exponent= str_to_vector(public_exponent);
	auto key_private_exponent= str_to_vector(private_exponent);

	uint8_t raw_data_hash[32];
	uint8_t result_data_hash[32];

	for (int i= 0; i<sample_size; i++){
		//Random
		auto raw_data= 
			random->GenerateRandomByteArray(data_length);

		//Hash	
		picosha2::hash256(raw_data, raw_data_hash, raw_data_hash+32);

		//Encrypt
		auto encrypt = 
			Rsa::Encrypt(key_modulus, key_public_exponent, raw_data);

		auto decrypt = 
			Rsa::Decrypt(key_modulus, key_private_exponent, encrypt);
		
		//Hash
		picosha2::hash256(
				decrypt, result_data_hash, result_data_hash+32);

		for (int i = 0; i<32; i++){
			if (raw_data_hash[i] != result_data_hash[i]){
				printf("Failed Cryptia\n");
				return 0;
			}
		}
	}

	printf("Compleate Cryptia\n");
	return 0;	
}
