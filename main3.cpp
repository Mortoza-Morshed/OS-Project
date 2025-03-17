#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <ctime>
#include <cstdlib>
#include <sys/stat.h>
#include <curl/curl.h>

// User Authentication
struct User {
    std::string username;
    std::string hashedPassword;
    std::string role;
    std::string email;
};

std::unordered_map<std::string, User> users;

std::string hashPassword(const std::string& password) {
    std::hash<std::string> hasher;
    return std::to_string(hasher(password));
}

void registerUser(const std::string& username, const std::string& password, const std::string& role, const std::string& email) {
    users[username] = {username, hashPassword(password), role, email};
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool verifyOTP(const std::string& email) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if (curl) {
        std::string url = "http://127.0.0.1:5000/send_otp";
        std::string jsonData = "{\"email\": \"" + email + "\"}";

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "cURL request failed: " << curl_easy_strerror(res) << std::endl;
            return false;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    std::string otp;
    std::cout << "Enter OTP received on email: ";
    std::cin >> otp;

    return readBuffer.find(otp) != std::string::npos;
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

    if (!verifyOTP(users[username].email)) {
        std::cout << "OTP verification failed!\n";
        return false;
    }

    std::cout << "Login successful!\n";
    return true;
}

// File Operations
void writeFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename);
    file << data;
    file.close();
    std::cout << "File written securely.\n";
}

void readFile(const std::string& filename) {
    std::ifstream file(filename);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::cout << "File Content: \n" << content << std::endl;
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

int main() {
    registerUser("admin", "password123", "Admin", "admin@example.com");
    registerUser("user", "userpass", "User", "user@example.com");

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
