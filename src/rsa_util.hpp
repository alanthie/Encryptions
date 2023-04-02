#ifndef RSA_UTIL_H_INCLUDED
#define RSA_UTIL_H_INCLUDED

#include "crypto_const.hpp"
#include "uint_util.hpp"
#include "qa/rsa_gen.hpp"
#include "file_util.hpp"

#ifdef _WIN32
//add preprocessor directive NOMINMAX
#pragma warning ( disable : 4146 )
#include "qa/RSA-GMP/RSAGMP.h"
#include "qa/RSA-GMP/RSAGMPUtils.h"
#else
// LINKER: -lgmp -lgmpxx
#include "qa/RSA-GMP/RSAGMP.h"
#include "qa/RSA-GMP/RSAGMPUtils.h"
#endif

#include <filesystem>
#include <iostream>
#include <fstream>

namespace rsa_util
{
	[[maybe_unused]] static bool get_rsa_key(const std::string& rsa_key_name, const std::string& local_rsa_db, cryptoAL::rsa::rsa_key& kout)
	{
		bool found = false;

		if (file_util::fileexists(local_rsa_db) == true)
		{
			std::map<std::string, cryptoAL::rsa::rsa_key> map_rsa;

			std::ifstream infile;
			infile.open (local_rsa_db, std::ios_base::in);
			infile >> bits(map_rsa);
			infile.close();

			for(auto& [userkey, k] : map_rsa)
			{
				if (userkey == rsa_key_name)
				{
					found = true;
					kout = k;
					break;
				}
			}
		}
		else
		{
			std::cout << "ERROR no rsa file: " << local_rsa_db << std::endl;
		}

		return found;
	}

    std::string rsa_decode_string(	const std::string& smsg, cryptoAL::rsa::rsa_key& k,
									uint32_t msg_input_size_touse, uint32_t& msg_size_produced, bool use_gmp)
	{
		std::string decoded_rsa_data;
		std::string msg;

		if (smsg.size() == msg_input_size_touse)
		{
            msg = smsg;
		}
		else if (msg_input_size_touse < smsg.size() )
		{
            msg = smsg.substr(0, msg_input_size_touse);
		}
		else
		{
            std::cout << "ERROR string to decode too big " << smsg.size() << " " << msg_input_size_touse << std::endl;
            throw "ERROR string to decode too big";
		}

		if (use_gmp == true)
		{
			RSAGMP::Utils::mpzBigInteger modulus(uint_util::base64_to_base10(k.s_n) );
			RSAGMP::Utils::mpzBigInteger priv(uint_util::base64_to_base10(k.s_d));
			RSAGMP::Utils::mpzBigInteger message(uint_util::base64_to_base10(msg));
			RSAGMP::Utils::mpzBigInteger message1 = RSAGMP::Decrypt(message, priv, modulus);
			decoded_rsa_data = uint_util::base10_to_base64(message1.get_str());
		}
		else
		{
			std::cout << "WARNING not using GMP" << std::endl;
			typeuinteger  v = uint_util::val(msg);
			decoded_rsa_data = k.decode(v);
		}
        msg_size_produced = (uint32_t)decoded_rsa_data.size();

		if (msg_input_size_touse < smsg.size() )
            decoded_rsa_data += smsg.substr(msg_input_size_touse);

		return decoded_rsa_data;
	}

	std::string rsa_encode_string(  const std::string& smsg, cryptoAL::rsa::rsa_key& k,
                                    uint32_t& msg_input_size_used, uint32_t& msg_size_produced,
                                    bool use_gmp, bool SELF_TEST)
	{
		std::string encoded_rsa_data;

		// smsg maybe less or bigger than rsa capacity
		std::string msg_to_encrypt;
		uint32_t key_len_bytes = k.key_size_in_bits / 8;

		if (key_len_bytes < smsg.size())
		{
			msg_to_encrypt = smsg.substr(0, key_len_bytes);
		}
		else
		{
			msg_to_encrypt = smsg;
		}
		msg_input_size_used = (uint32_t)msg_to_encrypt.size();

		if (use_gmp == true)
		{
			RSAGMP::Utils::mpzBigInteger modulus(uint_util::base64_to_base10(k.s_n) );
			RSAGMP::Utils::mpzBigInteger pub(uint_util::base64_to_base10(k.s_e));
			RSAGMP::Utils::mpzBigInteger message(uint_util::base64_to_base10(msg_to_encrypt));
			RSAGMP::Utils::mpzBigInteger message1 = RSAGMP::Encrypt(message, pub, modulus);
			std::string s_gmp = uint_util::base10_to_base64(message1.get_str());
			encoded_rsa_data = s_gmp;

			if (SELF_TEST)
			{
				RSAGMP::Utils::mpzBigInteger priv(uint_util::base64_to_base10(k.s_d));
				RSAGMP::Utils::mpzBigInteger message2 = RSAGMP::Decrypt(message1, priv, modulus);
				std::string s_gmp2 = uint_util::base10_to_base64(message2.get_str());
				if (s_gmp2 != msg_to_encrypt)
				{
					std::cout << "ERROR encryption decryption" << std::endl;
					std::cout << "s_gmp2:         " << file_util::get_summary_hex(s_gmp2.data(), (uint32_t)s_gmp2.size()) << " size:" << s_gmp2.size() << std::endl;
					std::cout << "msg_to_encrypt: " << file_util::get_summary_hex(msg_to_encrypt.data(), (uint32_t)msg_to_encrypt.size()) << " size:" << msg_to_encrypt.size() << std::endl;
					throw "ERROR encryption decryption";
				}
			}
		}
		else
		{
			std::cout << "WARNING not using GMP" << std::endl;
			typeuinteger  e = k.encode(msg_to_encrypt);
			encoded_rsa_data = uint_util::to_base64(e);
		}

		msg_size_produced = (uint32_t)encoded_rsa_data.size() ;
		//std::cout << "RSA encoding " << msg_to_encrypt.size() << " to " << encoded_rsa_data.size() << std::endl;

		if (msg_to_encrypt.size() < smsg.size())
		{
			encoded_rsa_data += smsg.substr(msg_to_encrypt.size());
		}

		//std::cout << "RSA encoding total size " << encoded_rsa_data.size() << std::endl;
		return encoded_rsa_data;
	}

}
#endif
