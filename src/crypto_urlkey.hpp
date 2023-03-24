#ifndef _INCLUDES_crypto_urlkey
#define _INCLUDES_crypto_urlkey

#include <filesystem>
#include <curl/curl.h>
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

	void clear_dynamic_data()
	{
		erase_buffer();
		sRSA_ECC_ENCODED_DATA.clear();
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

	std::string without_header_token()
	{
		if (url_size >= 3)
		{
			if ((url[0]=='[') &&  (url[2]==']'))
			{
				std::string s(url);
				return s.substr(3);
			}
		}
		else if (url_size > 0)
			return std::string(url);

		return "";
	}

	void set_url(const std::string& s)
	{
		for (size_t i=0; i < s.size(); i++)
		{
			if (i < URL_MAX_SIZE)
			{
				url[i] = s[i];
			}
			else
			{
                std::cerr << "ERROR url too big " << s << std::endl;
				throw "ERROR url too big ";
			}
		}
		if (s.size() < URL_MAX_SIZE)
		{
			url[s.size()] = 0;
			url_size = (uint16_t)s.size();
		}
		else
		{
            url_size = URL_MAX_SIZE-1;
		}
		url[URL_MAX_SIZE-1] = 0;
	}

	void do_checksum_data(cryptodata& data_temp)
    {
        SHA256 sha;
        sha.update(reinterpret_cast<const uint8_t*> (data_temp.buffer.getdata()), data_temp.buffer.size() );
        uint8_t* digest = sha.digest();
        auto s = SHA256::toString(digest);
        for( size_t j = 0; j< CHKSUM_SIZE; j++)
            checksum_data[j] = s[j];

        delete[] digest;
    }
    void do_checksum_key(cryptodata& data_temp)
    {
        SHA256 sha;
        sha.update(reinterpret_cast<const uint8_t*> (data_temp.buffer.getdata()), data_temp.buffer.size() );
        uint8_t* digest = sha.digest();
        auto s = SHA256::toString(digest);
        for( size_t j = 0; j< CHKSUM_SIZE; j++)
            checksum[j] = s[j];

        delete[] digest;
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

	uint32_t rsa_ecc_encoded_data_pad = 0;	// 4 bytes
	uint32_t rsa_ecc_encoded_data_len = 0;	// 4 bytes
	uint32_t rsa_ecc_encoded_data_pos = 0;	// 4 bytes

	uint32_t crypto_flags = 1;			// 4 bytes
	uint32_t shuffle_perc = 0;			// 4 bytes

    char urlinfo_with_padding[URLINFO_SIZE] = {0};
	std::string sRSA_ECC_ENCODED_DATA; 		// Base64 string of rsa_encoded_data_len // string's implementation uses memory on the heap.

protected:
    Buffer* buff_key = nullptr;
};


}
#endif

