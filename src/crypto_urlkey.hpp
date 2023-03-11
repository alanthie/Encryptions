#ifndef _INCLUDES_crypto_urlkey
#define _INCLUDES_crypto_urlkey

#include <filesystem>
#include <curl/curl.h>
#include "encrypt.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>
#include "base_const.hpp"
#include "crypto_const.hpp"
#include "crypto_parsing.hpp"

namespace cryptoAL
{

class urlkey
{
public:
    urlkey() {}
    ~urlkey()
    {
        if (buff_key != nullptr)
        {
            delete buff_key;
            buff_key = nullptr;
        }
    }

    Buffer* get_buffer()
    {
        if (buff_key == nullptr)
        {
            buff_key = new Buffer(MIN_KEY_SIZE);
        }
        return buff_key;
    }

    void erase_buffer()
    {
        if (buff_key != nullptr)
        {
            buff_key->erase();
        }
    }


    uint16_t crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_DES; // 2
    uint16_t url_size = 0;              // 2
    char url[URL_MAX_SIZE]= {0};        // 256x also buffer for rsa data embedded a key
    char magic[4]= {'a','b','c','d'};   // 4
    uint16_t key_fromH = 0;             // 2 random offset where to extract a key
    uint16_t key_fromL = 0;             // 2
    uint32_t key_size = MIN_KEY_SIZE;   // 4 bytes
    char key[MIN_KEY_SIZE] = {0};       // RSA KEY_NAME
    char checksum[CHKSUM_SIZE] = {0};   // 64 key
	char checksum_data[CHKSUM_SIZE] = {0};   // 64 data
	uint32_t rsa_encoded_data_pad = 0;	// 4 bytes
	uint32_t rsa_encoded_data_len = 0;	// 4 bytes
	uint32_t rsa_encoded_data_pos = 0;	// 4 bytes
	uint32_t crypto_flags = 1;			// 4 bytes
		
    char urlinfo_with_padding[URLINFO_SIZE] = {0};
	std::string sRSA_ENCODED_DATA; 		// Base64 string of rsa_encoded_data_len // string's implementation uses memory on the heap.
	
protected:
    Buffer* buff_key = nullptr;
};


}
#endif

