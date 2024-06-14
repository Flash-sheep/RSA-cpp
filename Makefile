# 编译器和编译选项
CXX = g++
CXXFLAGS =  -lgmpxx -lgmp -lcryptopp

# 目标
target: main.cpp Crypto.cpp RSAcipher.cpp
	$(CXX)  main.cpp Crypto.cpp RSAcipher.cpp -o target	$(CXXFLAGS)

# 清理
clean:
	rm -f target