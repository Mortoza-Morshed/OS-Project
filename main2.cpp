#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <ctime>
#include <cstdlib>
#include <sys/stat.h>

// User Authentication
struct User {
    std::string username;
    std::string hashedPassword;
    std::string role;
};

std::unordered_map<std::string, User> users;

std::string hashPassword(const std::string& password) {
    std::hash<std::string> hasher;
    return std::to_string(hasher(password));
}

void registerUser(const std::string& username, const std::string& password, const std::string& role) {
    users[username] = {username, hashPassword(password), role};
}

bool verifyOTP() {
    srand(time(0));
    int otp = rand() % 9000 + 1000;
    std::cout << "Your OTP: " << otp << "\nEnter OTP: ";
    int enteredOTP;
    std::cin >> enteredOTP;
    return otp == enteredOTP;
}

bool login(const std::string& username) {
    if (users.find(username) == users.end()) {
        std::cout << "User not found!\n";
        return false;
    }

    std::string password;
    std::cout << "Enter Password: ";
    std::cin >> password;

    if (users[username].hashedPassword != hashPassword(password)) {
        std::cout << "Incorrect password!\n";
        return false;
    }

    if (!verifyOTP()) {
        std::cout << "OTP verification failed!\n";
        return false;
    }

    std::cout << "Login successful!\n";
    return true;
}

// Security Functions (Encryption, Threat Detection)
std::string encrypt(const std::string& data) {
    std::string encrypted = data;
    for (char &c : encrypted) c += 3;
    return encrypted;
}

std::string decrypt(const std::string& encryptedData) {
    std::string decrypted = encryptedData;
    for (char &c : decrypted) c -= 3;
    return decrypted;
}

bool detectThreats(const std::string& filename) {
    std::ifstream file(filename);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    if (content.find("malware") != std::string::npos || content.length() > 1000000) {
        std::cout << "⚠️ Security Threat Detected in " << filename << "\n";
        return true;
    }
    return false;
}

// File Operations
void writeFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename);
    file << encrypt(data);
    file.close();
    std::cout << "File written securely.\n";
}

void readFile(const std::string& filename) {
    if (detectThreats(filename)) return;

    std::ifstream file(filename);
    std::string encryptedData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::cout << "Decrypted Content: \n" << decrypt(encryptedData) << std::endl;
}

void viewMetadata(const std::string& filename) {
    struct stat info;
    if (stat(filename.c_str(), &info) == 0) {
        std::cout << "File Size: " << info.st_size << " bytes\n";
        std::cout << "Last Modified: " << ctime(&info.st_mtime);
    } else {
        std::cout << "Metadata not available.\n";
    }
}

void shareFile(const std::string& filename) {
    std::string token = "SHARE123";
    std::cout << "File shared with token: " << token << "\n";
}

// Main Function
int main() {
    registerUser("admin", "password123", "Admin");
    registerUser("user", "userpass", "User");

    std::string username;
    std::cout << "Enter username: ";
    std::cin >> username;

    if (!login(username)) return 1;

    int choice;
    while (true) {
        std::cout << "\n1. Write File\n2. Read File\n3. View Metadata\n4. Share File\n5. Exit\nChoice: ";
        std::cin >> choice;

        std::string filename, data;
        switch (choice) {
            case 1:
                std::cout << "Enter filename: ";
                std::cin >> filename;
                std::cout << "Enter content: ";
                std::cin.ignore();
                std::getline(std::cin, data);
                writeFile(filename, data);
                break;
            case 2:
                std::cout << "Enter filename: ";
                std::cin >> filename;
                readFile(filename);
                break;
            case 3:
                std::cout << "Enter filename: ";
                std::cin >> filename;
                viewMetadata(filename);
                break;
            case 4:
                std::cout << "Enter filename: ";
                std::cin >> filename;
                shareFile(filename);
                break;
            case 5:
                return 0;
            default:
                std::cout << "Invalid choice.\n";
        }
    }
}
