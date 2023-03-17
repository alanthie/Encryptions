#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <ctype.h>

#include "vigenere.hpp"


namespace cryptoAL_vigenere
{

int index(char c)
{
	for(int ii = 0; ii < (int)AVAILABLE_CHARS.size(); ii++)
	{
		if(AVAILABLE_CHARS[ii] == c)
		{
			// std::cout << ii << " " << c << std::endl;
			return ii;
		}
	}
	return -1;
}

bool is_valid_string(std::string s)
{
    char c;
    unsigned char v;
    for(int ii = 0; ii < (int)s.size(); ii++)
    {
        c = s[ii];
        if (index(c) == -1)
        {
            v = (unsigned char)c;
            if ((v >= 32) && (v <= 127))
            {
                continue;
            }
            else
            {
                std::cerr << "Invalid char at position: " << ii << std::endl;
                return false;
            }
        }
    }
    return true;
}

std::string extend_key(std::string& msg, std::string& key)
{
	// generating new key
	int msgLen = (int)msg.size();
	std::string newKey(msgLen, 'x');

    int keyLen = (int)key.size();
    int i; int j;
	keyLen = keyLen;

    for(i = 0, j = 0; i < msgLen; ++i, ++j)
    {
        if (j == keyLen)
            j = 0;

        newKey[i] = key[j];
    }
    newKey[i] = '\0';
	return newKey;
}


std::string encrypt_vigenere(std::string& msg, std::string& key)
{
	int msgLen = (int)msg.size();
    int i = 0;

 	std::string encryptedMsg(msgLen, 'x');
    // char newKey[msgLen], encryptedMsg[msgLen], decryptedMsg[msgLen];

	std::string newKey = extend_key(msg, key);

    //encryption
    for(i = 0; i < msgLen; ++i)
    {
    	// std::cout << msg[i] << " " << isalnum(msg[i]) << std::endl;
    	if(isalnum(msg[i]) or msg[i] == ' ')
    	{
    		encryptedMsg[i] = AVAILABLE_CHARS[((index(msg[i]) + index(newKey[i])) % AVAILABLE_CHARS.size())];
    	}
    	else
    	{
    		encryptedMsg[i] = msg[i];
    	}
    }

    encryptedMsg[i] = '\0';
    return encryptedMsg;
}

std::string decrypt_vigenere(std::string& encryptedMsg, std::string& newKey)
{
	// decryption
	int msgLen = (int)encryptedMsg.size();
	std::string decryptedMsg(msgLen, 'x');
	int i;
    for(i = 0; i < msgLen; ++i)
    {
    	if(isalnum(encryptedMsg[i]) or encryptedMsg[i] == ' ')
    	{
    		decryptedMsg[i] = AVAILABLE_CHARS[(((index(encryptedMsg[i]) - index(newKey[i])) + AVAILABLE_CHARS.size()) % AVAILABLE_CHARS.size())];
    	}
    	else
    	{
    		decryptedMsg[i] = encryptedMsg[i];
    	}
    }
    decryptedMsg[i] = '\0';
	return decryptedMsg;
}

}


