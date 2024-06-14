#ifndef CRYPTO
#define CRYPTO
#include<gmpxx.h>
#include<cstring>
#include<fstream>
#include<vector>
#include<iomanip>
#include <cryptopp/aes.h>      // 包含AES加密算法的头文件
#include <cryptopp/filters.h>  // 包含加解密过程中使用的filters头文件
#include <cryptopp/modes.h>    // 包含加解密过程中使用的modes头文件
#include <cryptopp/hex.h>      // 包含将二进制转换为十六进制的头文件
#include<cryptopp/sha.h>
#include<cryptopp/osrng.h>
#include<cryptopp/rng.h>


using namespace std;
using namespace CryptoPP;
//this file defines math functions used in this project
mpz_class power(mpz_class a, mpz_class b, mpz_class c);
mpz_class mod_inverse(mpz_class a, mpz_class m);
bool miller_rabin(mpz_class n, unsigned long long int k);
mpz_class genPrime(unsigned long long int n);
mpz_class genRandom(unsigned long long int n);
mpz_class gcd(mpz_class a, mpz_class b);
int get_bit(mpz_class a);

//below are string operations
string readFile(const string&filename); //read plaintext from file
vector<string> readFiles(const string&filename);
void clearFile(const string&filename);
void writeFile(const string&filename,const string&data);
vector<string>groupString(const string& data,size_t n,size_t bit_per_char=8); //group string into n bit strings
vector<mpz_class> groupMpz(mpz_class data,size_t n); //group mpz into n bit mpzs;
string mergeStrings(const vector<string>&strings); //merge string groups into output
mpz_class stringToMpz(const string&data); //transform a string into mpz_class;
string mpzToString(const mpz_class&number); //transform a mpz into a string
string zeroPadding(const mpz_class&number,size_t n);
string oaepEncode(const string&data,size_t securityParam);
string oaepDecode(const string&data,size_t securityParam);

string getLowerString(const string&data,int n = 128);
string leftShift(const string&input,unsigned long long n);
string rightshift(const string&input,unsigned long long n);
string charToHex(const string&data); //transforms a char string to hex string, this may change the size ,ignore zeros
string hexToChar(const string&data);//transforms a hex string to char string
std::string bytes_to_hex(const std::string& bytes);
std::string hex_to_bytes(const std::string& hex);//this kind of change remains the length of original length

string xor_strings(const string& str1, const string& str2);


//below are some hash operations
string computeSHA512(const string&input);
string Int2OSP(int value,int length);
string generateMGF1(const string&seed,size_t outputLen);
#endif