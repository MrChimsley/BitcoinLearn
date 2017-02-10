#include <iostream>

#include "structs.cpp"




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


return 0;

}
