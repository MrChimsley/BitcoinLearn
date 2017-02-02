#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>


struct keydata {

    std::string private_key;
    std::string ext_private_key;
    std::string hash_ext_private_key;
    std::string hash_of_hash;
    std::string checksum;
    std::string hexwif;
    std::string base58_wif;
    std::string bytes ="";


    void processData(std::string privatekey){
        private_key=privatekey;
        ext_private_key = "80" + private_key;
        convertToBytes(ext_private_key);
        hash_ext_private_key = sha256(bytes);
        convertToBytes(hash_ext_private_key);
        hash_of_hash = sha256(bytes);
        checksum = hash_of_hash.substr(0,8);
        hexwif = ext_private_key + checksum;
        //base58_wif = base58encode(hexwif);
    }

    void convertToBytes(std::string hex){
        bytes="";
        int len = hex.length();
            for(int i=0; i< len; i+=2){
            std::string byte = hex.substr(i,2);
            unsigned char chr = (unsigned char) (int)strtol(byte.c_str(), NULL, 16);
            bytes+=chr;
                    }

    }

    std::string sha256(const std::string str){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, str.c_str(), str.size());
        SHA256_Final(hash, &sha256);
        std::stringstream ss;
            for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
            ss << std::hex << std::setw(2) << std::setfill('0') <<(int)hash[i];
            }
        return ss.str();
    }

};

int main()
{

keydata bitcoin;
std::string privatekey = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
bitcoin.processData(privatekey);

std::cout<<"Private Key     "<<bitcoin.private_key<<std::endl;  //0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
std::cout<<"Extended Key    "<<bitcoin.ext_private_key<<std::endl;// 800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
std::cout<<"Hash Extended   "<<bitcoin.hash_ext_private_key<<std::endl; //8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592
std::cout<<"Hash of hash    "<<bitcoin.hash_of_hash<<std::endl; //507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714
std::cout<<"Checksum bytes  "<<bitcoin.checksum<<std::endl; //507A5B8D
std::cout<<"WIF as Hex      "<<bitcoin.hexwif<<std::endl; //800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D
std::cout<<"WIF as Base58   "<<bitcoin.base58_wif<<std::endl; //5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
return 0;
}
