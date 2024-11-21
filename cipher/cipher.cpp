#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>

using namespace CryptoPP;

void encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& psw) {
    // Чтение данных из входного файла
    std::ifstream inFile(inputFile);
    if (!inFile) {
        std::cerr << "Не удалось открыть файл для чтения" << inputFile << std::endl;
    }
    std::string data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // Шифрование данных
    const int keyLength = AES::DEFAULT_KEYLENGTH;
    const int blockSize = AES::BLOCKSIZE;

    AutoSeededRandomPool prng;
    SecByteBlock key(keyLength);
    PKCS5_PBKDF2_HMAC<SHA224> pbkdf;

    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(psw.data()), psw.size(), nullptr, 0, 1000);
    
    byte iv[blockSize];
    prng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);

    std::vector<byte> cipherText;
    cipherText.resize(blockSize);
    std::copy(iv, iv + blockSize, cipherText.begin());

    StringSource ss(data, true,
        new StreamTransformationFilter(encryptor,
            new VectorSink(cipherText)));

    std::ofstream outFile(outputFile, std::ios::binary);
    outFile.write(reinterpret_cast<const char*>(cipherText.data()), cipherText.size());
    outFile.close();
    std::cout << "Зашифрование завершено " << std::endl;
}

void decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& psw) {
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Не удалось открыть файл для чтения"  << std::endl;
    }
    std::vector<byte> cipherText((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    const int keyLength = AES::DEFAULT_KEYLENGTH;
    const int blockSize = AES::BLOCKSIZE;

    SecByteBlock key(keyLength);
    PKCS5_PBKDF2_HMAC<SHA224> pbkdf;

    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(psw.data()), psw.size(), nullptr, 0, 1000);

    byte iv[blockSize];
    memcpy(iv, cipherText.data(), blockSize);

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);

    std::string decryptedText;

    StringSource ss(cipherText.data() + blockSize, cipherText.size() - blockSize, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(decryptedText)));

    std::ofstream outFile(outputFile);
    outFile << decryptedText;
    outFile.close();
    std::cout << "Расшифрование завершено" << std::endl;
}

int main() {
    std::string file1, file2, psw;
    int z;

    std::cout << "Введите режим (1 - зашифрование, 2 - расшифрование): ";
    std::cin >> z;

    std::cout << "Введите путь к файлу с исходными данными: ";
    std::cin >> file1;

    std::cout << "Введите путь к файлу для записи: ";
    std::cin >> file2;

    std::cout << "Введите пароль: ";
    std::cin >> psw;

    if (z == 1) {
        encrypt(file1, file2, psw);
    } else if (z == 2) {
        decrypt(file1, file2, psw);
    } else {
        std::cout << "Неверный режим.";
    }

    return 0;
}
