#ifndef CRYPTO_KEY_UTIL_HPP
#define CRYPTO_KEY_UTIL_HPP

#include "qa/mathcommon.h"
#include "crypto_const.hpp"
//#include "crypto_file.hpp"
#include "crypto_parsing.hpp"

#include "qa/RSA_generate/bigint/BigIntegerLibrary.hh"
using typeuinteger   = BigUnsigned;
using typebiginteger = BigInteger;

#include "c_plus_plus_serializer.h"

namespace cryptoAL
{
    //namespace key_util
    struct keyutil
    {
//        key_util()
//        {
//        };

        static int pos64(char c)
        {
            for(size_t  i=0;i<cryptoAL::BASEDIGIT64.size();i++)
            {
                if (c == cryptoAL::BASEDIGIT64[i])
                {
                    return (int)i;
                }
            }
            std::cerr << "ERROR pos64v invalid base 64 char " << (int)(unsigned char)c << std::endl;
            throw std::string("ERROR pos64() invalid base 64 char ");
            return 0;
        }

        static int pos10(char c)
        {
            for(size_t i=0;i<cryptoAL::BASEDIGIT10.size();i++)
            {
                if (c == cryptoAL::BASEDIGIT10[i])
                {
                    return (int)i;
                }
            }
            std::cerr << "ERROR invalid base 10 char " << (int)c << std::endl;
            throw "ERROR invalid base 10 char ";
            return 0;
        }

        static typeuinteger val(const std::string& s)
        {
            typeuinteger r = 0;
            long long n = (long long)s.size();
            for(long long i=0;i<n;i++)
            {
                r *= 64;
                r += pos64(s[i]);
            }
            return r;
        }
        static typeuinteger val10(const std::string& s)
        {
            typeuinteger r = 0;
            long long n = (long long)s.size();
            for(long long i=0;i<n;i++)
            {
                r *= 10;
                r += pos10(s[i]);
            }
            return r;
        }

        static typeuinteger mod_pow(typeuinteger base, typeuinteger exp, const typeuinteger& mod)
        {
            typeuinteger resoult = 1;

            while (exp > 0)
            {
                if (typeuinteger(exp & 1) == 1)
                    resoult = (base * resoult) % mod;
                base = (base * base) % mod;
                exp >>= 1;
            }

            return resoult;
        }

        static typeuinteger power_modulo(const typeuinteger& a, const typeuinteger& power, const typeuinteger& mod)
        {
            try
            {
                // windows stack overflow....
                // Visual Studio uses 4KB for the stack but reserved 1MB by default. You can change this in "Configuration Properties"->Linker->System->"Stack Reserve Size" to 10MB for example.
                // (a ⋅ b) mod m = [(a mod m) ⋅ (b mod m)] mod m
                if (power == 0) return 1;
                if (power % 2 == 1)
                {
                    return ((a % mod) * power_modulo(a, power - 1, mod)) % mod;
                }

                typeuinteger b = power_modulo(a, power / 2, mod) % mod;
                return (b * b) % mod;
            }
            catch (const std::exception& e)
            {
                std::cerr << "ERROR exception thrown in power_modulo " << e.what() << std::endl;
                throw e;
            }
            catch (...)
            {
                std::cerr << "ERROR exception thrown in power_modulo " << std::endl;
                throw std::string("ERROR exception thrown in power_modulo ");
            }
        }

        static std::string base10_to_base64(const std::string& s)
        {
            typeuinteger m = val10(s);
            return to_base64(m);
        }
        static std::string base64_to_base10(const std::string& s)
        {
            typeuinteger m = val(s);
            return to_base10(m);
        }

        static std::string to_base64(const typeuinteger& v)
        {
            typeuinteger r = v;
            typeuinteger b64 = 64;
            typeuinteger t;
            int digit;
            std::string s;
            while(r > 0)
            {
                t = (r % b64);
                digit = t.toInt();
                if (digit< 0) throw std::string("to base64 bad digit < 0");
                if (digit>63) throw std::string("to base64 bad digit > 63");
                s += cryptoAL::BASEDIGIT64[digit];
                r = r - digit;
                r = r / 64;
            }
            std::reverse(s.begin(), s.end());
            return s;
        }

        static std::string to_base10(const typeuinteger& v)
        {
            typeuinteger r = v;
            int digit;
            std::string s;
            typeuinteger t;
            typeuinteger b10 = 10;
            while(r > 0)
            {
                t = (r % b10);
                digit = t.toInt();
                if (digit<0) throw std::string("to base10 bad digit < 0");
                if (digit>9) throw std::string("to base10 bad digit > 9");
                s += cryptoAL::BASEDIGIT10[digit];
                r = r - digit;
                r = r / 10;
            }
            std::reverse(s.begin(), s.end());
            return s;
        }

		static void TEST()
        {
            std::string serr;

            if (to_base10(1234) != "1234")
            {
                serr = "Error with to_base10 1234";
                std::cerr << serr << std::endl;
                throw serr;
            }

            if (val10("456")  != 456)
            {
                serr = "Error with val10 456";
                std::cerr << serr << std::endl;
                throw serr;
            }

            if (val10("0456") != 456)
            {
                serr = "Error with val10 0456";
                std::cerr << serr << std::endl;
                throw serr;
            }

            typeuinteger m = val10("456");
            std::string m64 = to_base64(m);
            if (val(m64) != m)
            {
                serr = "Error with to_base64/val";
                std::cerr << serr << std::endl;
                throw serr;
            }

            m64 = base10_to_base64("456");
            if (val(m64) != 456)
            {
                serr = "Error with to_base10_to_base64";
                std::cerr << serr << std::endl;
                throw serr;
            }
        }

        static typeuinteger hex_to_uinteger(std::string s)
        {
            typeuinteger r = 0;
            long long n = (long long)s.size();
            for(long long i=0;i<n;i++)
            {
                r *= 16;
                if ((s[i]>= '0') && (s[i]<= '9') )
                    r += (s[i] - '0');
                else if ((s[i]>= 'a') && (s[i]<= 'f') )
                    r += 10 + (s[i] - 'a');
                else if ((s[i]>= 'A') && (s[i]<= 'F') )
                    r +=  10 + (s[i] - 'A');
                else
                   throw "invalid hex";
            }
            return r;
        }

        static bool eccfileexists(const std::filesystem::path& p, std::filesystem::file_status s = std::filesystem::file_status{})
        {
            if(std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists(p))
                return true;
            else
                return false;
        }

		static bool parse_ecc_domain(	const std::string& FILE, int& klen_inbits,
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

			s = cryptoAL::get_block_infile(FILE, "\"p\":" , "},");
			if (s.size() == 0) return false;
			{
                //std::cout << "s = " << s << std::endl;
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                p = hex_to_uinteger(t);
			}
			std::cout << "p = " << p << " bits: " << p.bitLength() << std::endl;

			klen_inbits = p.bitLength();

			s = cryptoAL::get_block_infile(FILE, "\"a\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                a = hex_to_uinteger(t);
			}
			std::cout << "a = " << a << " bits: " << a.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"b\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                b = hex_to_uinteger(t);
			}
			std::cout << "b = " << b << " bits: " << b.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"order\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                n = hex_to_uinteger(t);
			}
			std::cout << "n = " << n << " bits: " <<n.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"x\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                gx = hex_to_uinteger(t);
			}
			std::cout << "gx = " << gx << " bits: " << gx.bitLength() << std::endl;

			s = cryptoAL::get_block_infile(FILE, "\"y\":" , ",");
			if (s.size() == 0) return false;
			{
                std::string t = cryptoAL::remove_hex2_delim(s);
                //std::cout << "t = " << t << std::endl;
                gy = hex_to_uinteger(t);
			}
			std::cout << "gy = " << gy << " bits: " << gy.bitLength() << std::endl;

			h = 1;
			return true;
		 }

    };

}
#endif
