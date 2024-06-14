#ifndef RSACIPHER
#define RSACIPHER
#include"Crypto.h"
#include<iostream>
using namespace std;
struct RSApublicKey
{   
    mpz_class modulus;
    mpz_class publicExponent;
    // RSApublicKey(const RSApublicKey&a){
    //     modulus = a.modulus;
    // }
};

struct RSAprivateKey
{
    mpz_class modulus;
    mpz_class publicExponent;
    mpz_class privateExponent;
    mpz_class prime1;
    mpz_class prime2;
    mpz_class phiN;

    void verify(){
        cout<<"------check bits------"<<endl;
        cout<<"modulus is "<<get_bit(modulus) <<"bits"<<endl;
        cout<<"publicExponent is "<<get_bit(publicExponent) <<"bits"<<endl;
        cout<<"privateExponent is "<<get_bit(privateExponent) <<"bits"<<endl;
        cout<<"prime1 is "<<get_bit(prime1) <<"bits"<<endl;
        cout<<"prime2 is "<<get_bit(prime2) <<"bits"<<endl;
        cout<<"phiN is "<<get_bit(phiN) <<"bits"<<endl;

        cout<<"------check equations------"<<endl;
        cout<<"Is prime1 prime: "<<miller_rabin(prime1,get_bit(prime1))<<endl;
        cout<<"Is prime2 prime: "<<miller_rabin(prime2,get_bit(prime2))<<endl;
        cout<<"Is phiN correct: "<<(phiN==(prime1-1)*(prime2-1))<<endl;
        cout<<"Is publicExponent correct: "<<gcd(publicExponent,phiN)<<endl;
        cout<<"Is privateExponent correct: "<<(((publicExponent*privateExponent)%phiN)==1)<<endl;
    }

};




class RSAcipher{

public:
    RSApublicKey publicKey;
    RSAprivateKey privateKey;
    unsigned int securityParam;


    RSAcipher(unsigned int n=2048);
    // RSAcipher(const RSAcipher&);
    void genKey();//generate public key and private key

    mpz_class encrypt(const mpz_class& data);
    mpz_class decrypt(const mpz_class& data);
    mpz_class encrypt(const mpz_class& data,int padding);
    mpz_class decrypt(const mpz_class& data,int padding);
    string encrypt(const string&data,unsigned int base = 16,int padding=0); //get input string and output string
    string decrypt(const string& data,unsigned int base = 16,int padding=0);

    pair<mpz_class,mpz_class> getPublicKey()const; //N and e
    pair<mpz_class,mpz_class> getPrivateKey()const;//N and d
    void printParams()const; //print all params in privatekey

    void loadParams();//load params
};



#endif