#include"RSAcipher.h"
#include<iostream>
RSAcipher::RSAcipher(unsigned int n){
    std::cout<<"RSAcipher created"<<std::endl;
    securityParam = n;
}

// RSAcipher::RSAcipher(const RSAcipher&a){
//     std::cout<<"RSAcipher copied"<<std::endl;
//     publicKey = a.publicKey;
//     privateKey
// }

void RSAcipher::genKey(){
    unsigned int n = securityParam;
    privateKey.prime1 = genPrime(n);
    privateKey.prime2 = genPrime(n);
    privateKey.modulus= privateKey.prime1*privateKey.prime2;


    privateKey.phiN = (privateKey.prime1-1)*(privateKey.prime2-1);

    privateKey.publicExponent = 65537; //choose public key
    while(true){
        if(gcd(privateKey.publicExponent,privateKey.phiN)==1){
            break;
        }
        privateKey.publicExponent +=2;
    }

    privateKey.privateExponent = mod_inverse(privateKey.publicExponent,privateKey.phiN);

    publicKey.modulus = privateKey.modulus;
    publicKey.publicExponent = privateKey.publicExponent;
    std::cout<<"Private key and public key created"<<std::endl;
}

mpz_class RSAcipher::encrypt(const mpz_class& data){
    return power(data,publicKey.publicExponent,publicKey.modulus);
}

mpz_class RSAcipher::decrypt(const mpz_class& data){
    return power(data,privateKey.privateExponent,privateKey.modulus);
}

mpz_class RSAcipher::encrypt(const mpz_class& data,int padding){
    if(padding == 0){
        return power(data,publicKey.publicExponent,publicKey.modulus);
    }
    string msg = mpzToString(data);
    string oaepM = oaepEncode(msg,securityParam);
    mpz_class result = stringToMpz(oaepM);
    return power(result,publicKey.publicExponent,publicKey.modulus);
}

mpz_class RSAcipher::decrypt(const mpz_class& data,int padding){
    if(padding == 0){
        return power(data,privateKey.privateExponent,privateKey.modulus);
    }
    mpz_class oaepM = power(data,privateKey.privateExponent,privateKey.modulus);
    string outputPaddedhex = zeroPadding(oaepM,2*securityParam);
    string outputPad = hex_to_bytes(outputPaddedhex);

    return stringToMpz(oaepDecode(outputPad,securityParam));
}

string RSAcipher::encrypt(const string&data,unsigned int base,int padding){
    unsigned int groupBit;
    if(padding == 0){
        groupBit = securityParam; //Modulus
        cout<<"use zero padding\n";
    }
    else{
        groupBit = 2*securityParam-2*512-2*8;
        cout<<"use oaep padding\n";
    }

    
    vector<string>group = groupString(data,groupBit);//group the data
    // cout<<group.size()<<endl;
    string output;
    for(auto x:group){
        // cout<<x.length()<<' ';
        if(padding==0){
            // cout<<x<<endl;
            mpz_class slice = stringToMpz(x);
            // cout<<slice.get_str(16)<<endl<<bytes_to_hex(x)<<endl<<endl;
            // cout<<"is mpz of original text true: "<<(slice.get_str(16)==bytes_to_hex(x))<<endl; 
            // cout<<mpzToString(slice)<<endl;
            mpz_class result = power(slice,publicKey.publicExponent,publicKey.modulus);

            // cout<<"gcd"<<gcd(slice,privateKey.modulus)<<endl;
            // cout<<result.get_str(base)<<' '<<get_bit(result)<<' '<<zeroPadding(result,2*securityParam)<<endl;
            
            // mpz_class outputM1 = power(result,privateKey.privateExponent,privateKey.modulus);
            // cout<<"outputM1 == slice"<<(outputM1== slice)<<endl;
            // cout<<mpzToString(outputM1)<<endl;
            // cout<<slice.get_str(16)<<endl<<outputM1.get_str(16)<<endl;
            // cout<<(mpzToString(outputM1)==x)<<endl;

            string temp = zeroPadding(result,2*securityParam);
            output  = output+temp;


          

            mpz_class xM;
            xM.set_str(temp,base); //default to be 16 based

            mpz_class nonpadding;
            // cout<<result<<endl<<xM<<endl;

            // cout<<xM.get_str(base)<<' ';
            mpz_class outputM = power(xM,privateKey.privateExponent,privateKey.modulus);
            // cout<<"-------block--------"<<endl;
            // cout<<mpzToString(outputM)<<endl;
            // cout<<"-------block--------"<<endl;


        }
        else{
            //use padding strategy oaep
            string oaepX = oaepEncode(x,securityParam);
            mpz_class slice = stringToMpz(oaepX);
            // cout<<"is oeapx > modulus: "<<(slice>publicKey.modulus)<<endl;
            mpz_class result = power(slice,publicKey.publicExponent,publicKey.modulus);
            // cout<<result.get_str(base)<<' '<<get_bit(result)<<' '<<zeroPadding(result,2*securityParam)<<endl;
            output  = output+zeroPadding(result,2*securityParam);
        }
    }
    // cout<<endl;
    // cout<<output<<endl;
    cout<<"Encryption completed"<<endl;
    return output;
}

string RSAcipher::decrypt(const string& data,unsigned int base,int padding){


    string output;
    // cout<<data.length()<<endl;
    vector<string> group = groupString(data,2*securityParam,4); //here is only capable in 16 based
    // cout<<group.size()<<endl;
    for(auto x:group){

        if(padding == 0){
            mpz_class xM;
            xM.set_str(x,base); //default to be 16 based
            // cout<<xM.get_str(base)<<' ';

            mpz_class outputM = power(xM,privateKey.privateExponent,privateKey.modulus);
            // cout<<outputM.get_str(base)<<endl;
            output = output+mpzToString(outputM);
            // cout<<"-------block--------"<<endl;
            // cout<<mpzToString(outputM)<<endl;
            // cout<<"-------block--------"<<endl;
        }
        else{
            mpz_class xM;
            xM.set_str(x,base); //default to be 16 based
            // cout<<xM.get_str(base)<<' ';

            mpz_class outputM = power(xM,privateKey.privateExponent,privateKey.modulus);
            string outputPaddedhex = zeroPadding(outputM,2*securityParam); //convert to formal hex string
            string outputPad = hex_to_bytes(outputPaddedhex); //convert to formal char string
            // cout<<outputPaddedhex<<endl;
            
            output = output + oaepDecode(outputPad,securityParam);
            
        }
        
    }
    cout<<"Decryption completed"<<endl;
    
    return output;
}


pair<mpz_class,mpz_class> RSAcipher::getPublicKey()const{
    return pair<mpz_class,mpz_class>(publicKey.modulus,publicKey.publicExponent);

} //N and e

pair<mpz_class,mpz_class> RSAcipher::getPrivateKey()const{
    return pair<mpz_class,mpz_class>(0,0);
} //N and d
void RSAcipher::printParams()const{
        writeFile("RSA_Moduler.txt",publicKey.modulus.get_str(10));
        writeFile("RSA_p.txt",privateKey.prime1.get_str(10));
        writeFile("RSA_q.txt",privateKey.prime2.get_str(10));
        writeFile("RSA_Secret_key.txt",privateKey.privateExponent.get_str(10));
        writeFile("RSA_Public_key.txt",privateKey.publicExponent.get_str(10));
} //print all params in privatekey

void RSAcipher::loadParams(){
        publicKey.modulus.set_str(readFile("RSA_Moduler.txt"),10);
        privateKey.prime1.set_str(readFile("RSA_p.txt"),10);
        privateKey.prime2.set_str(readFile("RSA_q.txt"),10);
        privateKey.privateExponent.set_str(readFile("RSA_Secret_key.txt"),10);
        privateKey.publicExponent.set_str(readFile("RSA_Public_key.txt"),10);

        publicKey.publicExponent = privateKey.publicExponent;
        privateKey.modulus = publicKey.modulus;
        privateKey.phiN = (privateKey.prime1-1)*(privateKey.prime2-1);
}