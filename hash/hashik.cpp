#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
using namespace std;
std::string sha224(string f) {
	using namespace CryptoPP;
	SHA224 hash;
    string new_hash;
    FileSource file(f.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(new_hash))));
    return new_hash;
}
int main() {
  string file;
  cout << "Введите путь к файлу: ";
  cin >> file;
  string hash = sha224(file);
  cout << hash << endl;
  return 0;
}
