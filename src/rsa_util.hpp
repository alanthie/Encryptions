#ifndef RSA_UTIL_H_INCLUDED
#define RSA_UTIL_H_INCLUDED

#include "crypto_const.hpp"
#include "uint_util.hpp"
#include "qa/rsa_gen.hpp"
#include "file_util.hpp"
#include "crypto_parsing.hpp"

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

    [[maybe_unused]] static std::string rsa_decode_string(	const std::string& smsg, cryptoAL::rsa::rsa_key& k,
                                                            uint32_t msg_input_size_touse, uint32_t& msg_size_produced,
                                                            bool use_gmp, [[maybe_unused]] bool verbose=false)
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


	[[maybe_unused]] static std::string rsa_encode_string(  const std::string& smsg,
                                                            cryptoAL::rsa::rsa_key& k,
                                                            uint32_t& msg_input_size_used,
                                                            uint32_t& msg_size_produced,
                                                            bool use_gmp, bool SELF_TEST, [[maybe_unused]] bool verbose=false)
	{
		std::string encoded_rsa_data;

		// smsg maybe less or bigger than rsa capacity
		std::string msg_to_encrypt;
		uint32_t key_len_bytes = -1 + (k.key_size_in_bits / 8); // recursive may reach modulo p
        key_len_bytes = (uint32_t)(key_len_bytes * 1.33); // can take more with base64
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
		if (msg_to_encrypt.size() < smsg.size())
		{
			encoded_rsa_data += smsg.substr(msg_to_encrypt.size());
		}
		return encoded_rsa_data;
	}

	[[maybe_unused]] static std::string rsa_encode_full_string( const std::string& smsg, cryptoAL::rsa::rsa_key& k,
                                                                uint32_t& msg_size_produced,
                                                                bool use_gmp, bool SELF_TEST, bool verbose=false)
	{
		std::string r;
		std::string r_remaining = smsg;
		uint32_t required_encoded_msg_len = (uint32_t)smsg.size();
		uint32_t current_encoded_msg_len = 0;

		uint32_t t_msg_input_size_used;
		uint32_t t_msg_size_produced;
		uint32_t cnt = 0;
		std::string token_out;
		std::string token_in;
		while(current_encoded_msg_len < required_encoded_msg_len)
		{
			t_msg_input_size_used = 0;
			t_msg_size_produced   = 0;
			std::string t = rsa_encode_string(r_remaining, k, t_msg_input_size_used, t_msg_size_produced, use_gmp, SELF_TEST, verbose);

			if (t_msg_size_produced == 0)
			{
				std::cerr << "ERROR t_msg_size_produced == 0" << std::endl;
				break;
			}

			std::string s_size = uint_util::base10_to_base64(std::to_string(t_msg_size_produced));
			while(s_size.size() < 4) s_size = std::string("0") + s_size ;
			s_size = std::string("1") + s_size ; // 0 is trim later otherwise

			std::string s2_size = uint_util::base10_to_base64(std::to_string(t_msg_input_size_used));
			while(s2_size.size() < 4) s2_size = std::string("0") + s2_size ;
			s2_size = std::string("1") + s2_size ; // 0 is trim later otherwise

			r += s_size;
			r += s2_size;
			token_out = t.substr(0,t_msg_size_produced);
			r += token_out;
			token_in = r_remaining.substr(0, t_msg_input_size_used) ;

			cnt++;
			current_encoded_msg_len += t_msg_input_size_used;
			if (t_msg_input_size_used < r_remaining.size())
                r_remaining = r_remaining.substr(t_msg_input_size_used);
            else
                r_remaining = "";

            if (cryptoAL::VERBOSE_DEBUG)
			{
				if ((cnt <= 2) || (current_encoded_msg_len == required_encoded_msg_len))
				{
                    std::cout   << "(" << cnt << ") "
                                << t_msg_input_size_used << "-" << t_msg_size_produced
                                << "[" << token_in << "]"
                                << "==>[" << s_size + token_out << "]"<< std::endl;
                }
				else if (cnt==3)
				{
					std::cout << "..." << std::endl;
				}
			}
		}
		msg_size_produced = (uint32_t)r.size();

		if (cryptoAL::VERBOSE_DEBUG) std::cout << current_encoded_msg_len << "-" << msg_size_produced <<std::endl;
		return r;
	}

	[[maybe_unused]] static std::string rsa_decode_full_string(	const std::string& smsg, cryptoAL::rsa::rsa_key& k,
                                                                uint32_t& msg_size_produced, bool use_gmp, bool verbose=false)
	{
		bool ok = true;
		std::string r;
		std::vector<std::string> vr;
		uint32_t t_msg_size_produced;

		if (cryptoAL::VERBOSE_DEBUG)
			std::cout << "input size [" << smsg.size() << "]" << std::endl;

		std::string r_remaining = smsg;
		std::vector<std::string> v;
		std::vector<size_t> vinsz;
		while (r_remaining.size() > 10)
		{
            std::string s_size = r_remaining.substr(1, 4); // trim the first
            size_t v_size =  uint_util::val(s_size).toLong();

            std::string s2_size = r_remaining.substr(6, 4); // trim the first
            size_t v2_size =  uint_util::val(s2_size).toLong();

            if (r_remaining.size() >= 10 + v_size)
            {
                v.push_back(r_remaining.substr(10, v_size));
                vinsz.push_back(v2_size);
                if (r_remaining.size() > 10 + v_size)
                    r_remaining = r_remaining.substr(10 + v_size);
                else
					r_remaining = "";
            }
            else
            {
                std::cerr << "ERROR decoding RSA invalid length r_remaining.size() < 10 + v_size " << r_remaining.size() << " " << 10 + v_size << std::endl;
				ok = false;
				for(size_t i=0;i<v.size();i++)
				{
					std::cerr << v[i] << std::endl;
				}
				break;
            }
		}

		if (ok)
		{
			for(size_t i=0;i<v.size();i++)
			{
				if (v[i].size() > 0)
				{
					std::string t = rsa_decode_string(v[i], k, (uint32_t)v[i].size(), t_msg_size_produced, use_gmp, verbose);
					vr.push_back(t.substr(0, t_msg_size_produced));

					if (cryptoAL::VERBOSE_DEBUG)
					{
						if ((i<=1) || (i==v.size() - 1))
							std::cout << v[i].size() << "[" << v[i] << "]"<< "==>[" << t.substr(0, t_msg_size_produced) << "]"<< std::endl;
						else if (i==2)
							std::cout  << "..."<< std::endl;
					}
				}
			}

			uint32_t sz = 0;
			for(size_t i=0;i<vr.size();i++)
			{
                while(vr[i].size() < vinsz[i]) vr[i] = std::string("0") + vr[i];
				r  += vr[i];
				sz += (uint32_t)vr[i].size();
			}
			msg_size_produced = sz;
			if (cryptoAL::VERBOSE_DEBUG) std::cout << "output size: " << sz << std::endl;
		}
		return r;
	}

}
#endif
