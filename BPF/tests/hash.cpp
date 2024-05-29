#include <iostream>
#include <string>
#include <cstring>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include "unistd.h"

#include <iostream>
#include <fstream>
#include <string>

std::string calculateSHA256(const char* data, size_t length) {
    std::string hashStr;
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];

    hash.Update(reinterpret_cast<const CryptoPP::byte*>(data), length);
    hash.Final(digest);

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashStr), false);
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return hashStr;
}

std::string readFileContents(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка открытия файла: " << filePath << std::endl;
        return "";
    }

    std::string contents;
    file.seekg(0, std::ios::end);
    contents.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read(&contents[0], contents.size());
    file.close();

    return contents;
}

void getCodeSection(const char** start, size_t* length) {
    extern char __executable_start;
    extern char etext;
    *start = &__executable_start;
    *length = &etext - &__executable_start;
}

void beforeMain (void) __attribute__((constructor));
char expected_hash[100] = {0};

void beforeMain (void)
{
    std::string expectedHash;
    const char* codeStart;
    size_t codeLength;
    getCodeSection(&codeStart, &codeLength);
    expectedHash = calculateSHA256(codeStart, codeLength);
    std::cout << expectedHash << std::endl;
    memcpy(expected_hash, expectedHash.c_str(), 64);
}

int main() {
    sleep(5);
    const char* codeStart;
    size_t codeLength;
    getCodeSection(&codeStart, &codeLength);

    std::cout << "Code is running" << std::endl;
    std::string actualHash = readFileContents("./hash.txt");

    std::cout << "Expected hash: " + std::string(expected_hash) << std::endl;
    std::cout << "Actual hash: " + actualHash << std::endl;

    if (actualHash != std::string(expected_hash)) {
        std::cerr << "Instrumentation detected" << std::endl;
        return 1;
    }

    std::cout << "Program ended" << std::endl;

    return 0;
}