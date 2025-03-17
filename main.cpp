#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <vector>
#include <cstring>

using namespace std;

class SecureFileManager {
private:
    string hashedPassword;
    unsigned char key[32]; // AES-256 key size
    unsigned char iv[16] = {0}; // Initialization Vector

    string hashPassword(const string& password) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)password.c_str(), password.length(), hash);
        return string((char*)hash, SHA256_DIGEST_LENGTH);
    }

    vector<unsigned char> encrypt(const string& data) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        
        vector<unsigned char> encrypted(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int len = 0, encryptedLen = 0;
        EVP_EncryptUpdate(ctx, encrypted.data(), &len, (unsigned char*)data.c_str(), data.size());
        encryptedLen += len;
        EVP_EncryptFinal_ex(ctx, encrypted.data() + encryptedLen, &len);
        encryptedLen += len;
        encrypted.resize(encryptedLen);
        
        EVP_CIPHER_CTX_free(ctx);
        return encrypted;
    }

    string decrypt(const vector<unsigned char>& encryptedData) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        
        vector<unsigned char> decrypted(encryptedData.size());
        int len = 0, decryptedLen = 0;
        EVP_DecryptUpdate(ctx, decrypted.data(), &len, encryptedData.data(), encryptedData.size());
        decryptedLen += len;
        EVP_DecryptFinal_ex(ctx, decrypted.data() + decryptedLen, &len);
        decryptedLen += len;
        decrypted.resize(decryptedLen);
        
        EVP_CIPHER_CTX_free(ctx);
        return string(decrypted.begin(), decrypted.end());
    }

public:
    SecureFileManager(const string& password) {
        string hashed = hashPassword(password);
        memcpy(key, hashed.c_str(), 32); // Use first 32 bytes as AES-256 key
        hashedPassword = hashed;
    }

    bool authenticate(const string& password) {
        return hashPassword(password) == hashedPassword;
    }

    void writeFile(const string& filename, const string& content) {
        ofstream file(filename, ios::binary);
        if (!file) {
            cerr << "Error opening file for writing." << endl;
            return;
        }
        vector<unsigned char> encryptedData = encrypt(content);
        file.write((char*)encryptedData.data(), encryptedData.size());
        file.close();
    }

    void readFile(const string& filename) {
        ifstream file(filename, ios::binary);
        if (!file) {
            cerr << "Error opening file for reading." << endl;
            return;
        }
        vector<unsigned char> encryptedData((istreambuf_iterator<char>(file)), {});
        string decryptedData = decrypt(encryptedData);
        cout << "Decrypted Content: " << decryptedData << endl;
        file.close();
    }
};

int main() {
    string password;
    cout << "Set password: ";
    cin >> password;
    SecureFileManager manager(password);

    cout << "Enter password to authenticate: ";
    string inputPassword;
    cin >> inputPassword;

    if (!manager.authenticate(inputPassword)) {
        cout << "Authentication failed!" << endl;
        return 1;
    }

    string filename = "secure_data.dat";
    string content = "This is a secret message.";

    manager.writeFile(filename, content);
    manager.readFile(filename);
    return 0;
}
