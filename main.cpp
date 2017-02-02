#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <bitset>
#include <cstdlib>
#include <stdio.h>



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








int main()
{
//step 1
std::string step2 ="800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
unsigned long val = strtoul(step2.c_str(), 0, 16);
unsigned char * hashtarget = (unsigned char*)&val;
//std::cout<<sha256(p)<<std::endl;
std::cout<<val<<std::endl;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hashtarget, sizeof(hashtarget));
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
        ss << std::hex << std::setw(2) << std::setfill('0') <<(int)hash[i];
        }
std::cout<<ss.str()<<std::endl;





return 0;
}
