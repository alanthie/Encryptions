#ifndef ECC_UTIL_H_INCLUDED
#define ECC_UTIL_H_INCLUDED

#include "uint_util.hpp"
#include "crypto_const.hpp"
#include "../src/crypto_ecckey.hpp"
#include "../src/crypto_parsing.hpp"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <filesystem>


namespace ecc_util
{
	[[maybe_unused]] static bool eccfileexists(const std::filesystem::path& p, std::filesystem::file_status s = std::filesystem::file_status{})
	{
		if(std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists(p))
			return true;
		else
			return false;
	}

	[[maybe_unused]] static bool parse_ecc_domain(	const std::string& FILE, int& klen_inbits,
									typeuinteger& a, typeuinteger& b, typeuinteger& p,
									typeuinteger& n, typeuinteger& gx, typeuinteger& gy,
									typeuinteger& h)
	{
		if (eccfileexists(FILE) == false)
		{
			std::cerr << "no file: " << FILE << std::endl;
			return false;
		}

		std::string s;

		s = cryptoAL::parsing::get_block_infile(FILE, "\"p\":" , "},");
		if (s.size() == 0) return false;
		{
			//std::cout << "s = " << s << std::endl;
			std::string t = cryptoAL::parsing::remove_hex2_delim(s);
			//std::cout << "t = " << t << std::endl;
			p = uint_util::hex_to_uinteger(t);
		}
		std::cout << "p = " << p << " bits: " << p.bitLength() << std::endl;

		klen_inbits = p.bitLength();

		s = cryptoAL::parsing::get_block_infile(FILE, "\"a\":" , ",");
		if (s.size() == 0) return false;
		{
			std::string t = cryptoAL::parsing::remove_hex2_delim(s);
			//std::cout << "t = " << t << std::endl;
			a = uint_util::hex_to_uinteger(t);
		}
		std::cout << "a = " << a << " bits: " << a.bitLength() << std::endl;

		s = cryptoAL::parsing::get_block_infile(FILE, "\"b\":" , ",");
		if (s.size() == 0) return false;
		{
			std::string t = cryptoAL::parsing::remove_hex2_delim(s);
			//std::cout << "t = " << t << std::endl;
			b = uint_util::hex_to_uinteger(t);
		}
		std::cout << "b = " << b << " bits: " << b.bitLength() << std::endl;

		s = cryptoAL::parsing::get_block_infile(FILE, "\"order\":" , ",");
		if (s.size() == 0) return false;
		{
			std::string t = cryptoAL::parsing::remove_hex2_delim(s);
			//std::cout << "t = " << t << std::endl;
			n = uint_util::hex_to_uinteger(t);
		}
		std::cout << "n = " << n << " bits: " <<n.bitLength() << std::endl;

		s = cryptoAL::parsing::get_block_infile(FILE, "\"x\":" , ",");
		if (s.size() == 0) return false;
		{
			std::string t = cryptoAL::parsing::remove_hex2_delim(s);
			//std::cout << "t = " << t << std::endl;
			gx = uint_util::hex_to_uinteger(t);
		}
		std::cout << "gx = " << gx << " bits: " << gx.bitLength() << std::endl;

		s = cryptoAL::parsing::get_block_infile(FILE, "\"y\":" , ",");
		if (s.size() == 0) return false;
		{
			std::string t = cryptoAL::parsing::remove_hex2_delim(s);
			//std::cout << "t = " << t << std::endl;
			gy = uint_util::hex_to_uinteger(t);
		}
		std::cout << "gy = " << gy << " bits: " << gy.bitLength() << std::endl;

		h = 1;
		return true;
	 }

	[[maybe_unused]] static bool get_compatible_ecc_key(const std::string& local_ecc_mine_db, cryptoAL::ecc_key& key_other, cryptoAL::ecc_key& key_out_mine)
	{
		bool found = false;

		if (file_util::fileexists(local_ecc_mine_db) == true)
		{
			std::map<std::string, cryptoAL::ecc_key> map_ecc;

			std::ifstream infile;
			infile.open (local_ecc_mine_db, std::ios_base::in);
			infile >> bits(map_ecc);
			infile.close();

			for(auto& [userkey, k] : map_ecc)
			{
				if ((key_other.dom.name() == k.dom.name()) &&
					(key_other.dom.key_size_bits == k.dom.key_size_bits) )
				{
					found = true;
					key_out_mine = k;
					break;	// take first...
				}
			}
		}
		else
		{
			std::cout << "ERROR no ecc file: " << local_ecc_mine_db << std::endl;
		}

		return found;
	}

	[[maybe_unused]] static bool get_ecc_key(const std::string& ecc_key_name, const std::string& local_ecc_db, cryptoAL::ecc_key& kout)
	{
		bool found = false;

		if (file_util::fileexists(local_ecc_db) == true)
		{
			std::map<std::string, cryptoAL::ecc_key> map_ecc;

			std::ifstream infile;
			infile.open (local_ecc_db, std::ios_base::in);
			infile >> bits(map_ecc);
			infile.close();

			for(auto& [userkey, k] : map_ecc)
			{
				if (userkey == ecc_key_name)
				{
					found = true;
					kout = k;
					break;
				}
			}
		}
		else
		{
			std::cout << "ERROR no ecc file: " << local_ecc_db << std::endl;
		}

		return found;
	}
}
#endif
