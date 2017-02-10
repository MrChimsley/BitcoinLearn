#include <sstream>
#include <iomanip>
#include <algorithm>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <cstring>

struct keydata {

    std::string private_key;
    std::string ext_private_key;
    std::string hash_ext_private_key;
    std::string hash_of_hash;
    std::string checksum;
    std::string hexwif;
    std::string base58_wif="";
    std::string bytes ="";
    std::string tempstring;
    std::string code_string= "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";



    void processData(std::string privatekey){
        private_key=privatekey;
        ext_private_key = "80" + private_key;
        convertToBytes(ext_private_key);
        hash_ext_private_key = sha256(bytes);
        convertToBytes(hash_ext_private_key);
        hash_of_hash = sha256(bytes);
        checksum = hash_of_hash.substr(0,8);
        hexwif = ext_private_key + checksum;

        tempstring=hexwif;

            while(tempstring.length()>1){
                base58encode();
            }
        std::reverse(base58_wif.begin(),base58_wif.end());

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

    void hex2char(){
        char string_array[hexwif.length()+1];
        strcpy(string_array, hexwif.c_str());
    }


    void base58encode(){

        char string_array[tempstring.length()+1];
        strcpy(string_array,tempstring.c_str());
        BIGNUM *bn1 = NULL;
        BIGNUM *bn2 = NULL;
        BIGNUM *remainder = BN_new();
        BIGNUM *quotient = BN_new();
        BIGNUM *zero = 0;
        BN_CTX *bn_ctx = BN_CTX_new();

        BN_dec2bn(&bn1, "58");
        BN_hex2bn(&bn2, string_array);
        BN_div(quotient,remainder, bn2, bn1, bn_ctx );

        int rvalue=atoi(BN_bn2dec(remainder));

        base58_wif+=(code_string.substr(rvalue,1));
        tempstring=BN_bn2hex(quotient);

        BN_free(bn1);
        BN_free(bn2);
        BN_free(remainder);
        BN_CTX_free(bn_ctx);



    }


};
