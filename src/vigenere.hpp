#ifndef vigenere_HPP
#define vigenere_HPP

#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <ctype.h>

namespace cryptoAL_vigenere
{
    static std::string AVAILABLE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

    int index(char c);
    bool is_valid_string(std::string s);
    std::string extend_key(std::string& msg, std::string& key);
    std::string encrypt_vigenere(std::string& msg, std::string& key);
    std::string decrypt_vigenere(std::string& encryptedMsg, std::string& newKey);

}
#endif // vigenere_HPP
