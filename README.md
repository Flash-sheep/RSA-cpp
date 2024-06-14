# RSA-cpp
This is a repository for c++ implementation of RSA encryption, including the textbook RSA, CCA2 attack on textbook RSA and OAEP padding for RSA
### Preparation

This work is configured on Linux OS. If you're using Windows or other OS, you may encounter configuration problems for GMP installation( as I was).

#### Download GMP library

referring to this [Linux 下安装GMP库_gmp安装-CSDN博客](https://blog.csdn.net/just_h/article/details/82667787)

#### Download Crypto++ 

Simply using apt command

`sudo apt install libcrypto++-dev`



### Run the program

`make` then `./target`

### Task1 

In task1, I implemented the simple textbook version of RSA.

The procedure of testing textbook RSA is encapsulated into a function 'RSA()' in main.cpp. Add RSA() into main() run the program.

Change "Raw_Message.txt" to change the plaintext and encrypted message will be  output into "Encrypted_Message.txt"

### Task2

In task2, I implemented the CCA2 attack on RSA in "CCA2()".

Add "CCA2()" to "Main()" and run to see the results.

### Task3

In task3, I implemented the OAEP padding of RSA in "RSA_OAEP()".

Also I tested CCA2 attack of OAEP padding in "CCA2_OAEP()", and run it to see that in this context, the attack is ineffective.

The detailed introduction of this program is in "网络安全技术大作业-RSA.pdf"

