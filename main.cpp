#include<gmpxx.h>
#include<iostream>
#include"RSAcipher.h"
#include <chrono>

using namespace std;
using namespace CryptoPP;


// bool isPrime(const mpz_class&p,unsigned long long int n){
//     mpz_powm_ui
// }

class Server{
private:
    RSAcipher rsa;

    string aesEncrypt(const string&plaintext,const string&aesKey){
        byte iv[AES::BLOCKSIZE];
        memset(iv, 0x00, AES::BLOCKSIZE);   //assume iv to be all-zero
        CBC_Mode<AES>::Encryption encryption((byte *)aesKey.c_str(), aesKey.length(), iv);
        string ciphertext;
        StringSource(plaintext, true, new StreamTransformationFilter(encryption, new StringSink(ciphertext)));
        return ciphertext;
    }

    string aesDecrypt(const string&ciphertext,const string&aesKey){
        byte iv[AES::BLOCKSIZE];
        memset(iv, 0x00, AES::BLOCKSIZE); //assume iv to be all-zero
        CBC_Mode<AES>::Decryption decryption((byte *)aesKey.c_str(), aesKey.length(), iv);
        string decryptedtext;
        StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decryptedtext)));
        return decryptedtext;
    }
public:
    Server(RSAcipher origin):rsa(origin){
        cout<<"Server initiated"<<endl;
    }


    string setSession(const string&rsaEncKey,const string&aesEncWup,int base = 16,int padding = 0){ // user use this op to establish session with the server, if complished, it returns a encrypted response
        string aesKey = rsa.decrypt(rsaEncKey,16,padding);//get the decrypted ase key

        // cout<<aesKey<<endl;
        //to chop off the lowest 128 bit of aesKey
        // mpz_class aesKeyM;
        // aesKeyM.set_str(aesKey,base);
        // aesKeyM = aesKeyM & ((mpz_class(1)<<128)-1);

        // cout<<aesKeyM<<endl;

        //use the chop off key to decrypt message
        cout<<"aesKey is "<<aesKey<<endl;
        string aesKeyC = getLowerString(aesKey);
        cout<<"aesKeyC is "<<aesKeyC<<endl;

        string wup = aesDecrypt(aesEncWup,aesKeyC);
    

        //decide whether is a legal wup
        if(wup.length()<5) return "";
        if(wup.substr(0,5)!="Hello") return "";

        string response = "Session established!";
        return aesEncrypt(response,aesKeyC);//return a response

        return wup;


    }

    string setSession(const mpz_class&rsaEncKey,const string&aesEncWup,int base = 16,int padding=0){ // user use this op to establish session with the server, if complished, it returns a encrypted response
        mpz_class aesKey = rsa.decrypt(rsaEncKey,padding);//get the decrypted ase key

        // cout<<aesKey<<endl;
        //to chop off the lowest 128 bit of aesKey
        // mpz_class aesKeyM;
        // aesKeyM.set_str(aesKey,base);
        // aesKeyM = aesKeyM & ((mpz_class(1)<<128)-1);

        // cout<<aesKeyM<<endl;

        //use the chop off key to decrypt message
        aesKey = aesKey & ((mpz_class(1)<<128)-1);

        string aesKeyC = mpzToString(aesKey);
        // string aesKeyC = mpzToString(rsaEncKey);
        string wup;

        try
        {
            wup = aesDecrypt(aesEncWup,aesKeyC);
        }
        catch(const std::exception& e)
        {
            return "";
        }
             

        //decide whether is a legal wup
        if(wup.length()<5) return "";
        if(wup.substr(0,5)!="Hello") return "";

        string response = "Session established!";
        return aesEncrypt(response,aesKeyC);//return a response

        return wup;


    }


    
};

class Client{
private:


    RSAcipher rsa;
    string aesEncrypt(const string&plaintext,const string&aesKey){
        byte iv[AES::BLOCKSIZE];
        memset(iv, 0x00, AES::BLOCKSIZE);   //assume iv to be all-zero
        CBC_Mode<AES>::Encryption encryption((byte *)aesKey.c_str(), aesKey.length(), iv);
        string ciphertext;
        StringSource(plaintext, true, new StreamTransformationFilter(encryption, new StringSink(ciphertext)));
        return ciphertext;
    }

    string aesDecrypt(const string&ciphertext,const string&aesKey){
        byte iv[AES::BLOCKSIZE];
        memset(iv, 0x00, AES::BLOCKSIZE); //assume iv to be all-zero
        CBC_Mode<AES>::Decryption decryption((byte *)aesKey.c_str(), aesKey.length(), iv);
        string decryptedtext;
        StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decryptedtext)));
        return decryptedtext;
    }

public:
    Client(RSAcipher origin):rsa(origin){
        cout<<"Client initiated"<<endl;
    }

    string genEncAes(const string&aesKey,int padding =0){
        string encAesKey = rsa.encrypt(aesKey,16,padding);
        // cout<<encAesKey<<endl;
        return encAesKey;
    }

    string decrypt(const string&aesKey,const string&Wup){
        return aesDecrypt(Wup,aesKey);
    }

    string genEncWup(const string&aesKey,string Wup = "Hello there"){
        
        string aesEncWup = aesEncrypt(Wup,aesKey);
        // cout<<"aesencwup is:"<<stringToMpz(aesEncWup).get_str(16)<<endl;
        return aesEncWup;
    }

    mpz_class genEncAes(const mpz_class&aesKey,int padding =0){
        mpz_class encAesKey = rsa.encrypt(aesKey,padding);
        // cout<<encAesKey<<endl;
        return encAesKey;
    }

    string genEncWup(const mpz_class&aesKey,string Wup = "Hello there"){
        
        string aesKeystring = mpzToString(aesKey);

        string aesEncWup = aesEncrypt(Wup,aesKeystring);
        // cout<<"aesencwup is:"<<stringToMpz(aesEncWup).get_str(16)<<endl;
        return aesEncWup;
    }

    bool verifyResponse(const string&response,const string&aesKey){
        if(response.empty()) return false;
        string DecRes = aesDecrypt(response,aesKey);
        if(DecRes == "Session established!")return true;

        return false;
    }
    bool verifyResponse(const string&response,const mpz_class&aesKey){
        if(response.empty()) return false;
        string aesKeystring = mpzToString(aesKey);

        string DecRes = aesDecrypt(response,aesKeystring);
        if(DecRes == "Session established!")return true;

        return false;
    }

};

void CCA2(){ //an implementation of cca2 
    bool write = true;
    if(write){
        clearFile("AES_Key.txt");
        clearFile("WUP_Requst.txt");
        clearFile("AES_Encrypted_WUP.txt");
        clearFile("History_messages.txt");

    }
    RSAcipher rsa(1024);
    // rsa.genKey();
    rsa.loadParams();
    auto publickey = rsa.getPublicKey();

    //-----initiate server client and attacker-------
    cout<<"-----initiate server client and attacker-------"<<endl;
    Server server(rsa);
    Client client(rsa);
    Client attacker(rsa);// attacker and client were not supposed to get private key, here is a simplified implement

    //-----communication between client and server
    cout<<"-----communication between client and server-------"<<endl;
    string key = "0123456789012345"; //client generated key
    string wup = "Hello Server"; //client generated wup request
    cout<<"client generated key:"<<key<<endl;
    cout<<"client generated WUP:"<<wup<<endl;
    mpz_class keyM = stringToMpz(key);

    mpz_class rsaEncKeyM = client.genEncAes(keyM); //client encrypt key with rsa
    string aesEncWup = client.genEncWup(keyM,wup); //client encrypt wup with aes

    if(write){
        writeFile("AES_Key.txt",keyM.get_str(16));
        writeFile("WUP_Requst.txt",charToHex(wup));
        writeFile("AES_Encrypted_WUP.txt",charToHex(aesEncWup));
        writeFile("History_messages.txt",rsaEncKeyM.get_str(16)+"\n");
        writeFile("History_messages.txt",charToHex(aesEncWup));
    } //write log messeges

    string response = server.setSession(rsaEncKeyM,aesEncWup);//response from server

    if(client.verifyResponse(response,keyM)){
        cout<<"Has connection to server"<<endl;
    }
    else{
        cout<<"Connection failure!!"<<endl;
    }

    cout<<"-----attacker begin attacking using CCA2-------"<<endl;
    //-----attacker begin attacking using CCA2

    mpz_class keyAttack = 0; //store current found bits of key
    vector<string>historyMessage = readFiles("History_messages.txt");

    string getkey = historyMessage[0]; //get rsa encrypted aes key
    // cout<<getkey<<endl;
    string getwup = historyMessage[1];

    cout<<"attacker has rsa encrypted aes key and aes encrypted wup"<<endl;

    mpz_class encKey;
    encKey.set_str(getkey,16);

    // cout<<mpzToString(rsa.decrypt(encKey))<<endl;

    for(int i =127;i>=0;i--){ //traverse from 127 to 0
        cout<<"trying bit "<<127-i<<endl;
        mpz_class rsaEncKeyT = (encKey<<(i*publickey.second.get_si()))%publickey.first; //Ci the rsa enc of ki

        mpz_class keyT = (mpz_class(1)<<127)+(keyAttack<<i); //always make sure the highest bit of 128 is 1,and follows already known bits
        
        // cout<<get_bit(keyT)<<endl;

        string attEncWup = attacker.genEncWup(keyT,"Hello I am attacker");

        
        string res = server.setSession(rsaEncKeyT,attEncWup);
        // string res = server.setSession(attEncAes,attEncWup);

        if(attacker.verifyResponse(res,keyT)){
            // guess is true,set 1
            keyAttack += (mpz_class(1)<<(127-i));
            // cout<<"bit "<<127-i<<" is "<<1<<endl;
            continue;
        }

        // cout<<"bit "<<127-i<<" is "<<0<<endl;
        //guess is false, set 0
    }
    cout<<"guess key is "<<mpzToString(keyAttack)<<endl;

    cout<<"use guess key to decrypt client WUP:"<<attacker.decrypt(mpzToString(keyAttack),hexToChar(getwup))<<endl;


}

void CCA2_OAEP(){ //an implementation of cca2 
    bool write = true;
    if(write){
        clearFile("AES_Key.txt");
        clearFile("WUP_Requst.txt");
        clearFile("AES_Encrypted_WUP.txt");
        clearFile("History_messages.txt");
    }

    RSAcipher rsa(1024);
    // rsa.genKey();
    rsa.loadParams();
    auto publickey = rsa.getPublicKey();

    //-----initiate server client and attacker-------
    cout<<"-----initiate server client and attacker-------"<<endl;
    Server server(rsa);
    Client client(rsa);
    Client attacker(rsa);// attacker and client were not supposed to get private key, here is a simplified implement

    //-----communication between client and server
    cout<<"-----communication between client and server-------"<<endl;
    string key = "0123456789012345"; //client generated key
    string wup = "Hello Server"; //client generated wup request
    cout<<"client generated key:"<<key<<endl;
    cout<<"client generated WUP:"<<wup<<endl;
    mpz_class keyM = stringToMpz(key);

    mpz_class rsaEncKeyM = client.genEncAes(keyM,1); //client encrypt key with rsa
    string aesEncWup = client.genEncWup(keyM,wup); //client encrypt wup with aes

    if(write){
        writeFile("AES_Key.txt",keyM.get_str(16));
        writeFile("WUP_Requst.txt",charToHex(wup));
        writeFile("AES_Encrypted_WUP.txt",charToHex(aesEncWup));
        writeFile("History_messages.txt",rsaEncKeyM.get_str(16)+"\n");
        writeFile("History_messages.txt",charToHex(aesEncWup));
    } //write log messeges

    string response = server.setSession(rsaEncKeyM,aesEncWup,16,1);//response from server

    if(client.verifyResponse(response,keyM)){
        cout<<"Has connection to server"<<endl;
    }
    else{
        cout<<"Connection failure!!"<<endl;
    }

    cout<<"-----attacker begin attacking using CCA2-------"<<endl;
    //-----attacker begin attacking using CCA2

    mpz_class keyAttack = 0; //store current found bits of key
    vector<string>historyMessage = readFiles("History_messages.txt");

    string getkey = historyMessage[0]; //get rsa encrypted aes key
    // cout<<getkey<<endl;
    string getwup = historyMessage[1];

    cout<<"attacker has rsa encrypted aes key and aes encrypted wup"<<endl;

    mpz_class encKey;
    encKey.set_str(getkey,16);

    // cout<<mpzToString(rsa.decrypt(encKey,1))<<endl;

    for(int i =127;i>=0;i--){ //traverse from 127 to 0
        cout<<"trying bit "<<127-i<<endl;
        mpz_class rsaEncKeyT = (encKey<<(i*publickey.second.get_si()))%publickey.first; //Ci the rsa enc of ki

        mpz_class keyT = (mpz_class(1)<<127)+(keyAttack<<i); //always make sure the highest bit of 128 is 1,and follows already known bits
        
        // cout<<get_bit(keyT)<<endl;

        string attEncWup = attacker.genEncWup(keyT,"Hello I am attacker");

        
        string res = server.setSession(rsaEncKeyT,attEncWup,16,1);
        // string res = server.setSession(attEncAes,attEncWup);

        if(attacker.verifyResponse(res,keyT)){
            // guess is true,set 1
            keyAttack += (mpz_class(1)<<(127-i));
            // cout<<"bit "<<127-i<<" is "<<1<<endl;
            continue;
        }

        // cout<<"bit "<<127-i<<" is "<<0<<endl;
        //guess is false, set 0
    }
    cout<<"guess key is "<<mpzToString(keyAttack)<<endl;

    try{
        cout<<"use guess key to decrypt client WUP:\n"<<attacker.decrypt(mpzToString(keyAttack),hexToChar(getwup))<<endl;
    }
    catch(exception&e){
        cout<<"unable to decrypt\n"<<"error message is:"<<e.what()<<endl;
    }
    


}

void RSA(){
    bool write = true;
    clearFile("Encrypted_Message.txt");

    if(write){
        clearFile("RSA_Moduler.txt");
        clearFile("RSA_p.txt");
        clearFile("RSA_q.txt");
        clearFile("RSA_Secret_key.txt");
        clearFile("RSA_Public_key.txt");
    }


    RSAcipher rsa(1024);
    rsa.genKey();
    // rsa.loadParams();

    if(write) rsa.printParams();

    string m = readFile("Raw_Message.txt");
    // string m  = "123";
    string ciphertext1 = rsa.encrypt(m);
    writeFile("Encrypted_Message.txt",ciphertext1);
    string ciphertext2 = readFile("Encrypted_Message.txt");

    // cout<<(ciphertext1==ciphertext2)<<endl;

    
    string plaintext = rsa.decrypt(ciphertext2);

    cout<<"----Decrypted Plaintext----\n";
    cout<<plaintext<<endl;

    cout<<"----Verify Plaintext----\n";
    cout<<"Is plaintext and raw message the same: "<<(plaintext==m)<<endl;

    
}



void RSA_OAEP(){
    bool write = false;
    clearFile("Encrypted_Message.txt");

    if(write){
        clearFile("RSA_Moduler.txt");
        clearFile("RSA_p.txt");
        clearFile("RSA_q.txt");
        clearFile("RSA_Secret_key.txt");
        clearFile("RSA_Public_key.txt");
    }


    RSAcipher rsa(1024);
    // rsa.genKey();
    rsa.loadParams();
    if(write)rsa.printParams();

    string m = readFile("Raw_Message.txt");
    // string m = "123";

    string ciphertext_oaep = rsa.encrypt(m,16,1);

    // cout<<ciphertext.length()<<endl<<ciphertext_oaep.length()<<endl;
    
    writeFile("Encrypted_Message.txt",ciphertext_oaep);
    
    string ciphertext = readFile("Encrypted_Message.txt");

    // cout<<static_cast<int>(ciphertext.back())<<endl;

    // teststring(ciphertext);
    string plaintext = rsa.decrypt(ciphertext,16,1);

    cout<<"----Decrypted Plaintext----\n";

    // cout<<plaintext.length()<<endl<<(plaintext == m)<<endl;
    cout<<plaintext<<endl;

    cout<<"----Verify Plaintext----\n";
    cout<<"Is plaintext and raw message the same: "<<(plaintext==m)<<endl;
}
int main(){
    // CCA2();
    // RSA_OAEP();
    cout<<"Welcome to my project of cpp\n";
    int count = 0;
    int n;
    while(true){

        cout<<"enter:\n"<<"0 - task1\n"<<"1 - task2\n"<<"2 - task3\n"<<"3 - CCA2 attack of task3\n"<<"4 - exit\n";
        cin>>n;

        if(n==4) break;

        if(count==0&&n!=0){
            cout<<"run task1 first!!\n";
            continue;
        }
        switch (n)
        {
        case 0:
            RSA();
            break;
        case 1:
            CCA2();
            break;
        case 2:
            RSA_OAEP();
            break;
        case 3:
            CCA2_OAEP();
            break;
        
        default:
            exit(0);
            break;
        }
        count++;

    }
    return 0;
}