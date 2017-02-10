#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "structs.cpp"
#include <cstring>



int main()
{


keydata bitcoin;

std::string privatekey = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
bitcoin.processData(privatekey);

std::cout<<"Private Key     "<<bitcoin.private_key<<std::endl;
std::cout<<"Extended Key    "<<bitcoin.ext_private_key<<std::endl;
std::cout<<"Hash Extended   "<<bitcoin.hash_ext_private_key<<std::endl;
std::cout<<"Hash of hash    "<<bitcoin.hash_of_hash<<std::endl;
std::cout<<"Checksum bytes  "<<bitcoin.checksum<<std::endl;
std::cout<<"WIF as Hex      "<<bitcoin.hexwif<<std::endl;
std::cout<<"WIF as Base58   "<<bitcoin.base58_wif<<std::endl;



/*
char string_array[bitcoin.hexwif.length()+1];
strcpy(string_array,bitcoin.hexwif.c_str());
	BIGNUM *bn1 = NULL;
	BIGNUM *bn2 = NULL;
	BIGNUM *result = BN_new();
	BIGNUM *quotient = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();

	BN_dec2bn(&bn1, "58");
	BN_hex2bn(&bn2, string_array);

	BN_div(quotient,result, bn2, bn1, bn_ctx );
	std::cout<<BN_bn2dec(quotient)<<std::endl;
	std::cout<<BN_bn2dec(result)<<std::endl;



	BN_free(bn1);
	BN_free(bn2);
	BN_free(result);
    BN_CTX_free(bn_ctx);
*/



return 0;

}
