#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

void encrypt(const std::string& inputf, const std::string& outputf, const std::string& psw)
{
    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(psw.data()), psw.size(), nullptr, 0, 1000);
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);
    FileSink fileSink(outputf.c_str());
    fileSink.Put(iv, AES::BLOCKSIZE);
    FileSource fileSource(inputf.c_str(), true, new StreamTransformationFilter(encryptor, new Redirector(fileSink), BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
    fileSource.PumpAll();
}

void decrypt(const std::string& inputf, const std::string& outputf, const std::string& psw)
{
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(psw.data()), psw.size(), nullptr, 0, 1000);
    byte iv[AES::BLOCKSIZE];
    FileSource(inputf.c_str(), true, new ArraySink(iv, AES::BLOCKSIZE));
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);
    FileSource fileSource(inputf.c_str(), true, new StreamTransformationFilter(decryptor, new FileSink(outputf.c_str()), BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
    fileSource.PumpAll();
}
int main()
{
    std::string file1, file2, psw;
    int z;

    std::cout << "Введите режим (1 - зашифрование, 2 - расшифрование) ";
    std::cin >> z;

    std::cout << "Введите путь к файлу с исходными данными: ";
    std::cin >> file1;

    std::cout << "Введите путь к файлу для записи: ";
    std::cin >> file2;

    std::cout << "Введите пароль: ";
    std::cin >> psw;
    
    if (z == 1) {
        encrypt(file1, file2, psw);
        std::cout << "Зашифрование успешно.\n";
    } else if (z == 2) {
        decrypt(file1, file2, psw);
        std::cout << "Расшифрование успешно.\n";
    }
    return 0;
}
