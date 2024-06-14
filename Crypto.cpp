#include"Crypto.h"
#include<iostream>
#include <chrono>
#include<algorithm>
mpz_class power(mpz_class a, mpz_class b, mpz_class c) {
    mpz_class res = 1;
    a = a % c;
    while (b > 0) {
        if (b % 2 == 1)
            res = (res * a) % c;
        b = b >> 1;
        a = (a * a) % c;
    }
    return res;
}


mpz_class mod_inverse(mpz_class a, mpz_class m){
    mpz_class m0 = m,t,q;
    mpz_class x0 = 0, x1 = 1;
    if(m==1)
        return 0;
    
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

bool miller_rabin(mpz_class n, unsigned long long int k) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;


    unsigned long seed = std::chrono::system_clock::now().time_since_epoch().count();
    gmp_randclass rand_obj(gmp_randinit_default);
    rand_obj.seed(seed);


    mpz_class d = n - 1;
    unsigned long long int s = 0;
    while (d % 2 == 0) {
        d /= 2;
        s++;
    }

    for (unsigned long long int i = 0; i < k; i++) {
        // 生成一个随机数 a 在 [2, n-2] 范围内
        mpz_class a = (rand_obj.get_z_range(n) % (n - 2)) + 2;

        mpz_class x = power(a, d, n);
        if (x == 1 || x == n - 1)
            continue;

        for (unsigned long long int  r = 1; r < s; r++) {
            x = power(x, 2, n);
            if (x == n - 1)
                break;
        }
        if (x != n - 1)
            return false;
    }

    return true;
}

mpz_class genPrime(unsigned long long int n){
    unsigned long long int i  = 1;
    unsigned long seed = std::chrono::system_clock::now().time_since_epoch().count();
    gmp_randclass rand_obj(gmp_randinit_default);
    rand_obj.seed(seed);
    mpz_class one = 1;

    for(i=1;i<3*n*n;i++){
        mpz_class pp = (one<<(n-1))+rand_obj.get_z_bits(n-1); //generate a random uniforom number of n-bit
        // cout<<pp<<endl;
        if(miller_rabin(pp,n)) return pp;
    }
    return -1;
}
mpz_class genRandom(unsigned long long int n){
    unsigned long seed = std::chrono::system_clock::now().time_since_epoch().count();
    gmp_randclass rand_obj(gmp_randinit_default);
    rand_obj.seed(seed);
    return rand_obj.get_z_bits(n);
}

mpz_class gcd(mpz_class a, mpz_class b) {
    while (b != 0) {
        mpz_class t = b;
        b = a % b;
        a = t;
    }
    return a;
}

int get_bit(mpz_class a){
    int count =0;
    while(a){
        a/=2;
        count++;
    }
    return count;
}

string readFile(const string&filename){
    ifstream file(filename,std::ios::in);
    if(!file.is_open()){
        std:cerr<<"Error opening file: "<< filename<<endl;
        return "";
    }

    // string content;
    // string line;
    // while(getline(file,line)){
    //     content+=line+"\n";
    // }
    std::string fileContents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return fileContents;
}

vector<string> readFiles(const string&filename){
    ifstream file(filename,std::ios::in);
    vector<string> outputs;
    if(!file.is_open()){
        std:cerr<<"Error opening file: "<< filename<<endl;
        return outputs;
    }

    string content;
    string line;
    while(getline(file,line)){
        outputs.emplace_back(line);
    }
    file.close();
    return outputs;
}

void clearFile(const string&filename){
    std::ofstream outputFile;

    // 以截断模式打开文件
    outputFile.open(filename, std::ios::out | std::ios::trunc);
    if (outputFile.is_open()) {
        std::cout << filename<<" cleared successfully." << std::endl;
        outputFile.close(); // 关闭文件
    } else {
        std::cerr << "Unable to open file." << std::endl;
    }
}



void writeFile(const string&filename,const string&data){
    ofstream outputFile;
    outputFile.open(filename,ios::app);
    if(outputFile.is_open()){
        outputFile<<data;
        cout<<filename<<"written"<<endl;
        outputFile.close();
    }
    else{
        cerr<<"Unable to open file"<<endl;
    }
}

vector<string>groupString(const string& data,size_t n,size_t bit_per_char){
    // size_t byteSize = strlen(data.c_str());
    size_t byteSize = data.length();
    // cout<<"bytesize"<<byteSize<<endl;
    n = n/bit_per_char; //transform bit width into byte width
    // cout<<"group decrypt "<<n<<endl;
    vector<string> chunks;

    for(size_t i = 0; i<byteSize;i+=n){
        // cout<<"group"<<i<<"created"<<endl;
        chunks.emplace_back(data.substr(i,n));
    }

    return chunks;
}

string mergeStrings(const vector<string>&strings){
    string content;
    for(auto x:strings){
        content+=x;
    }
    return content;
}

mpz_class stringToMpz(const string&data){
    mpz_class result =0;
    for(char c:data){
        result = (result<<8) | static_cast<uint8_t>(c); //leftshift and add
    }
    return result;
}

string mpzToString(const mpz_class&number){
    string result;
    // string number_str = number.get_str();
    mpz_class temp = number;

    while(temp){
        result  =  static_cast<char>(temp.get_ui()&0xFF)+result; //rightshift and add
        temp >>=8;
    }

    return result;
}

vector<mpz_class> groupMpz(mpz_class data,size_t n){
    size_t part_size = n/8;
    
    vector<mpz_class>output;

    while(data){
        mpz_class temp = data & ((mpz_class(1)<<n)-1); //get lower n bit;
        data >>=n;
        output.emplace_back(temp);
    }
    reverse(output.begin(),output.end());
    return output;
}

string zeroPadding(const mpz_class&number,size_t n){
    //only used for 16 based output
    int bits = get_bit(number);
    
    int padding = (n-bits)/4;
    // cout<<"n-bits"<<n-bits<<"padding"<<padding<<endl;
    string pad ;
    for(int i =0;i<padding;i++){
        pad+="0";
    }
    return pad+number.get_str(16);
}

string oaepEncode(const string&data,size_t securityParam){
    size_t hLen = 512/8;
    size_t k = 2*securityParam/8;
    size_t DBLen = k-1-hLen;
    size_t PSLen = DBLen - 1-data.length()-hLen;


    cout<<"generate hash\n";
    mpz_class seed = genRandom(512);
    string seedEx = generateMGF1(mpzToString(seed),DBLen);

    string l = "this is a string of l";
    string lHash = computeSHA512(l);

    string PS;
    for(size_t i = 0;i<PSLen;i++){
        PS = PS + static_cast<char>(0x00);
    }

    string DB = lHash+PS+static_cast<char>(0x01)+data;

    // cout<<"DB generated: "<<DB<<endl;

    // cout<<seedEx.length()<<' '<<DB.length()<<endl;
    string maskedDB = xor_strings(seedEx,DB);
    
    string maskedDBEx = generateMGF1(maskedDB,hLen);

    string maskedSeed = xor_strings(maskedDBEx,mpzToString(seed));
    
    string EM = static_cast<char>(0x00) + maskedSeed + maskedDB;

    // cout<<"maskedSeed is "<<bytes_to_hex(maskedSeed)<<endl;
    // cout<<"maskedDB is "<<bytes_to_hex(maskedDB)<<endl;
    // cout<<"seedEx is "<<bytes_to_hex(seedEx)<<endl;
    // cout<<"maskedDBEx is "<<bytes_to_hex(maskedDBEx)<<endl;
    return EM;
}

string oaepDecode(const string&data,size_t securityParam){
    size_t hLen = 512/8;
    size_t k = 2*securityParam/8;
    size_t DBLen = k-1-hLen;

    string maskedSeed = data.substr(1,hLen);
    string maskedDB = data.substr(1+hLen);

    // cout<<"maskedSeed is "<<bytes_to_hex(maskedSeed)<<endl;
    // cout<<"maskedDB is "<<bytes_to_hex(maskedDB)<<endl;

    string maskedDBEx = generateMGF1(maskedDB,hLen);

    string seed = xor_strings(maskedDBEx,maskedSeed);

    string seedEx = generateMGF1(seed,DBLen);

    // cout<<"seedEx is "<<bytes_to_hex(seedEx)<<endl;
    // cout<<"maskedDBEx is "<<bytes_to_hex(maskedDBEx)<<endl;

    
    string DB = xor_strings(seedEx,maskedDB);

    int mstart=0;
    for(int i=hLen;i<DBLen;i++){
        if(DB[i]==static_cast<char>(0x01)){
            mstart = i+1;
            break;
        }
    }
    if(mstart ==0 ){
        cerr<<"the message is not properly decoded"<<endl;
    }

    return DB.substr(mstart);//get rest as message

}

string getLowerString(const string&data,int n){
    mpz_class dataM = stringToMpz(data);
    // cout<<dataM.get_str(2)<<endl;
    dataM = dataM & ((mpz_class(1)<<n)-1);
    // cout<<dataM.get_str(2)<<endl;
    return mpzToString(dataM);
}


string leftShift(const string&input,unsigned long long n){
    mpz_class inputM = stringToMpz(input);
    // cout<<inputM.get_str(2)<<endl;
    inputM = inputM << n;
    // cout<<inputM.get_str(2)<<endl;
    return mpzToString(inputM);
}

string rightshift(const string&input,unsigned long long n){
    mpz_class inputM = stringToMpz(input);
    inputM = inputM >> n;
    return mpzToString(inputM);
}

string charToHex(const string&data){
    mpz_class temp = stringToMpz(data);
    // cout<<temp<<endl;
    return temp.get_str(16);
}

string hexToChar(const string&data){
    mpz_class temp;
    temp.set_str(data,16);
    return mpzToString(temp);
}

std::string bytes_to_hex(const std::string& bytes){
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (unsigned char c : bytes) {
        ss << std::setw(2) << static_cast<int>(c);
    }

    return ss.str();
}

std::string hex_to_bytes(const std::string& hex){
    std::stringstream ss;
    std::string bytes;

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        char c = static_cast<char>(std::stoi(byte, nullptr, 16));
        bytes += c;
    }

    return bytes;
}

string xor_strings(const string& str1, const string& str2){
    if (str1.length() != str2.length()) {
        throw std::runtime_error("Strings must be of equal length");
    }

    std::string result;
    result.reserve(str1.length());

    for (size_t i = 0; i < str1.length(); ++i) {
        result += static_cast<char>(static_cast<unsigned char>(str1[i]) ^ static_cast<unsigned char>(str2[i]));
    }

    return result;
}



string computeSHA512(const string&input){
    SHA512 sha512;
    string digest;
    StringSource(input, true, new HashFilter(sha512, new HexEncoder(new StringSink(digest))));
    return hexToChar(digest);
}

string Int2OSP(int value,int length){
    string result;
    for(int i= length-1;i>=0;i--){
        result =  static_cast<char>(value & 0xFF)+result;
        value>>=8;
    }
    return result;
}
string generateMGF1(const string&seed,size_t outputLen){
    //use sha-512
    const int hashLen = 512/8;
    int counter = 0;
    
    string result;
    while(outputLen-result.length()>=hashLen){
        string hash = computeSHA512(seed+Int2OSP(counter,4));
        result = result + hash;
        counter++;
    }
    string hash = computeSHA512(seed+Int2OSP(counter,4));
    result = result + hash.substr(0,outputLen-result.length());
    return result;
}

