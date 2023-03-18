#ifndef COMMONKEY_H_INCLUDED
#define COMMONKEY_H_INCLUDED

#include "qa/mathcommon.h"
#include "base_const.hpp"

#ifdef USING_uinteger_t
//
#else
#include "qa/RSA_generate/bigint/BigIntegerLibrary.hh"
using typeuinteger   = BigUnsigned;
using typebiginteger = BigInteger;
#endif

#include "c_plus_plus_serializer.h"

namespace cryptoAL
{
    struct key_util
    {
        key_util()
        {
        };

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

            if (cryptoAL::key_util::to_base10(1234) != "1234")
            {
                serr = "Error with to_base10 1234";
                std::cerr << serr << std::endl;
                throw serr;
            }

            if (cryptoAL::key_util::val10("456")  != 456)
            {
                serr = "Error with val10 456";
                std::cerr << serr << std::endl;
                throw serr;
            }

            if (cryptoAL::key_util::val10("0456") != 456)
            {
                serr = "Error with val10 0456";
                std::cerr << serr << std::endl;
                throw serr;
            }

            typeuinteger m = cryptoAL::key_util::val10("456");
            std::string m64 = cryptoAL::key_util::to_base64(m);
            if (cryptoAL::key_util::val(m64) != m)
            {
                serr = "Error with to_base64/val";
                std::cerr << serr << std::endl;
                throw serr;
            }

            m64 = cryptoAL::key_util::base10_to_base64("456");
            if (cryptoAL::key_util::val(m64) != 456)
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

		static bool parse_ecc_domain(	const std::string& FILE, int& klen_inbits,
                                        typeuinteger& a, typeuinteger& b, typeuinteger& p,
                                        typeuinteger& n, typeuinteger& gx, typeuinteger& gy,
                                        typeuinteger& h)
     	{
/*
./ecgen --fp -v -m 8g -u -p -r 1024
seadata not found, this will probably take quite some time.
[
+++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++-++++++++
{
    "field": {
        "p": "0xc6ed729cf6e4ef61dfe8bf98b03b7c22c635603c0cd1c5b1888e4c4f6dbfbca51fc3421e6d432495d317fff4a3cc48a98be49f062c78deaf8a95877ebb56a4374a526381b12d9425c986f74e7e59d66d10fd354a12740896fc5cdae9e4b7c17fc6d48fc0e0cdf0e405a1e94b8ad2baf8d1fd2f3d1d0a55f7dcbcf45d8cc1f69f"
    },
    "a": "0x7d19dbd19ca7c0770f6110d75725ffc095279b90e826959c9d88569c6ba00043535ccac1b96060c3037d59e15208e7470896d3ba3fd8363e75ff1bdb5764187e381936c60453a44893f5c0d521eb7e40bd6c1e0f0c415c10823b017093e6de2b53c0330bb45dc23faae124bd001c8c92b15b2771e9cebfabbaa06b73d2ea60b3",
    "b": "0x62cf2ed3b803ced3250498b2d280f03836937c35d607106a2a7cd39f0280d1af537be6ebb5234ccf07bd6a8b78ab6dd816bea900b5f3faecc8a7536d591fa786603672061b240a4373341b126caadf6cc07dceb2783665889da756f88cb8928898ae62fb3ef06fbcf2ba791dce16bd989754401b51c3845ecb5fe7c5230eefca",
    "order": "0xc6ed729cf6e4ef61dfe8bf98b03b7c22c635603c0cd1c5b1888e4c4f6dbfbca51fc3421e6d432495d317fff4a3cc48a98be49f062c78deaf8a95877ebb56a43873681ca3cbcf53a8de471ce1514210ef54ca46e8d65a42d97f0dbeb2767a5d15d6c95fa4680a2d0e5b132099f1379629d2bc5de7d3829252aeef6a32e904ed41",
    "subgroups": [
        {
            "x": "0xac20dd5de7d2bd2f3807feaa4cb6ad8f4863db8f882bcc91666eb99de5ead96ddfdec28c910026f80a9ef60e271dcea6a71365cc412a558d3d288db4dab722e15a11af60cf9f03412a600089ffab151adb32c3ad1c5e1764b7e0256884f538453c72527ee2dee9a7b67e5716ff47223af1cc5c7d50296fc4b614fbbd3f925760",
            "y": "0x29d03f1027c7d51f01de87fdb59c3c390a2ed182c1a766f20a5ebb29982df71b380aaa86fc2909b2fd8dad1c431fd5ddd0244253059265ea37c0c1d359817f70bb3629fc0e9ede52ed049eb0c0e04ed34be34bd6053cd90c273208f2fb8c7c5a6a1359e9536cf25870339111016788abd9ce8552548673a0adf3a3c42f67d828",
            "order": "0xc6ed729cf6e4ef61dfe8bf98b03b7c22c635603c0cd1c5b1888e4c4f6dbfbca51fc3421e6d432495d317fff4a3cc48a98be49f062c78deaf8a95877ebb56a43873681ca3cbcf53a8de471ce1514210ef54ca46e8d65a42d97f0dbeb2767a5d15d6c95fa4680a2d0e5b132099f1379629d2bc5de7d3829252aeef6a32e904ed41",
            "cofactor": "0x1",
            "points": [
                {
                    "x": "0xac20dd5de7d2bd2f3807feaa4cb6ad8f4863db8f882bcc91666eb99de5ead96ddfdec28c910026f80a9ef60e271dcea6a71365cc412a558d3d288db4dab722e15a11af60cf9f03412a600089ffab151adb32c3ad1c5e1764b7e0256884f538453c72527ee2dee9a7b67e5716ff47223af1cc5c7d50296fc4b614fbbd3f925760",
                    "y": "0x29d03f1027c7d51f01de87fdb59c3c390a2ed182c1a766f20a5ebb29982df71b380aaa86fc2909b2fd8dad1c431fd5ddd0244253059265ea37c0c1d359817f70bb3629fc0e9ede52ed049eb0c0e04ed34be34bd6053cd90c273208f2fb8c7c5a6a1359e9536cf25870339111016788abd9ce8552548673a0adf3a3c42f67d828",
                    "order": "0xc6ed729cf6e4ef61dfe8bf98b03b7c22c635603c0cd1c5b1888e4c4f6dbfbca51fc3421e6d432495d317fff4a3cc48a98be49f062c78deaf8a95877ebb56a43873681ca3cbcf53a8de471ce1514210ef54ca46e8d65a42d97f0dbeb2767a5d15d6c95fa4680a2d0e5b132099f1379629d2bc5de7d3829252aeef6a32e904ed41"
                }
            ]
        }
    ]
}]
*/
			if (cryptoAL::fileexists2(FILE) == false)
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
