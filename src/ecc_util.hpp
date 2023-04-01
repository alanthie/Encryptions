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
}
#endif
