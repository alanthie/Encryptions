#ifndef RSAGEN_H_INCLUDED
#define RSAGEN_H_INCLUDED

#include "mathcommon.h"
#include "../base_const.hpp"

// TODO - BUG in uinteger_t and BigInteger with modulus() for very big number
//#define USING_uinteger_t 1
#ifdef USING_uinteger_t
#include "BigInteger.h"
using typeuinteger   = uinteger_t;
using typebiginteger = big_number::BigInteger;
#else
#include "RSA_generate/bigint/BigIntegerLibrary.hh"
using typeuinteger   = BigUnsigned;
using typebiginteger = BigInteger;
#endif

#include "../c_plus_plus_serializer.h"

namespace generate_rsa
{
#ifdef USING_uinteger_t
    typeuinteger to_uinteger(typebiginteger a);
    typebiginteger to_biginteger(typeuinteger a);
#endif

    struct rsa_key
    {
        rsa_key()
        {
        };

        void TEST()
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
        };


        rsa_key(int key_size__bits, const std::string& a, const std::string& b, const std::string& c)
        {
            key_size_in_bits = key_size__bits;
            s_n = a;
            s_e = b;
            s_d = c;
        }

        uint32_t key_size_in_bits = 2048; 
        std::string s_n; // base 64
        std::string s_e; // base 64
        std::string s_d; // base 64 empty if public key

        friend std::ostream& operator<<(std::ostream &out, Bits<rsa_key & > my)
        {
            out << bits(my.t.key_size_in_bits) << bits(my.t.s_n) << bits(my.t.s_e) << bits(my.t.s_d);
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<rsa_key &> my)
        {
            in >> bits(my.t.key_size_in_bits) >> bits(my.t.s_n) >> bits(my.t.s_e) >> bits(my.t.s_d);
            return (in);
        }

        int pos64(char c)
        {
            for(size_t  i=0;i<cryptoAL::BASEDIGIT64.size();i++)
            {
                if (c == cryptoAL::BASEDIGIT64[i])
                {
                    return (int)i;
                }
            }
            std::cerr << "ERROR pos64 invalid base 64 char " << (int)(unsigned char)c << std::endl;
            throw "ERROR pos64 invalid base 64 char ";
            return 0;
        }

        int pos10(char c)
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

        typeuinteger val(const std::string& s)
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
        typeuinteger val10(const std::string& s)
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

        typeuinteger get_n() { return val(s_n);}
        typeuinteger get_e() { return val(s_e);}
        typeuinteger get_d() { return val(s_d);}

        typeuinteger mod_pow(typeuinteger base, typeuinteger exp, const typeuinteger& mod)
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

        typeuinteger power_modulo(const typeuinteger& a, const typeuinteger& power, const typeuinteger& mod)
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

        typeuinteger encode(const std::string& s)
        {
            typeuinteger n = get_n();
            typeuinteger m = val(s);
            typeuinteger r = mod_pow(m, get_e(), n);
            return r;
        }

        std::string decode(const typeuinteger& v)
        {
            typeuinteger n = get_n();
            typeuinteger m = v;
            typeuinteger r = mod_pow(m, get_d(), n);
            std::string s = to_base64(r);
            return s;
        }

        std::string base10_to_base64(const std::string& s)
        {
            typeuinteger m = val10(s);
            return to_base64(m);
        }
        std::string base64_to_base10(const std::string& s)
        {
            typeuinteger m = val(s);
            return to_base10(m);
        }

        std::string to_base64(const typeuinteger& v)
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
                if (digit<0) throw "bad digit";
                if (digit>63) throw "bad digit";
                s += cryptoAL::BASEDIGIT64[digit];
                r = r - digit;
                r = r / 64;
            }
            std::reverse(s.begin(), s.end());
            return s;
        }

        std::string to_base10(const typeuinteger& v)
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
                if (digit<0) throw "bad digit";
                if (digit>69) throw "bad digit";
                s += cryptoAL::BASEDIGIT10[digit];
                r = r - digit;
                r = r / 10;
            }
            std::reverse(s.begin(), s.end());
            return s;
        }
    };

    // SSH RSA Private Key ASN.1
    // totient = (key.prime1 - 1) * (key.prime2 - 1);
    // public  key n, e
    // private key n, d
    // Encryption C = pow(M,e) % n [M < n]
    // Encryption M = pow(C,d) % n
    struct PRIVATE_KEY
    {
        int         	version;
        uint32_t    	key_size_in_bits = 2048;
        typeuinteger 	modulus;            // n = key.modulus = key.prime1 * key.prime2;
        typeuinteger 	publicExponent;     // e = key.publicExponent  = FindPublicKeyExponent(totient, 8);
        typeuinteger 	privateExponent;    // d = key.privateExponent = ModInverse(key.publicExponent, totient); // decryption exponent
		
		// Not use:
        typeuinteger prime1;             // p
        typeuinteger prime2;             // q
        typeuinteger exponent1;          // key.exponent1 = key.privateExponent % (key.prime1 - 1);
        typeuinteger exponent2;          // key.exponent2 = key.privateExponent % (key.prime2 - 1);
        typeuinteger coefficient;        // key.coefficient = ModInverse(key.prime2, key.prime1);

        void to_rsa_key(rsa_key& rkey, const typeuinteger& n, const typeuinteger& e, const typeuinteger& d, uint32_t keysize_in_bits)
        {
            rkey.key_size_in_bits = keysize_in_bits;
            {
                std::stringstream ss;
                ss << n ; // base 10
                rkey.s_n = rkey.base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << e ;
                rkey.s_e = rkey.base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << d ;
                rkey.s_d = rkey.base10_to_base64(ss.str());
            }
/*
            std::cout << "-----------------------------" << std::endl;
            std::cout << "key_size_in_bits " << rkey.key_size_in_bits<< std::endl;
            std::cout << "modulus "         << rkey.s_n << std::endl;
            std::cout << "publicExponent "  << rkey.s_e << std::endl;
            std::cout << "privateExponent " << rkey.s_d << std::endl;
            std::cout << "-----------------------------" << std::endl;
*/
        }

        void to_rsa_key(rsa_key& rkey)
        {
            rkey.key_size_in_bits = key_size_in_bits;

            {
                std::stringstream ss;
                ss << modulus ; // base 10
                rkey.s_n = rkey.base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << publicExponent ;
                rkey.s_e = rkey.base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << privateExponent ;
                rkey.s_d = rkey.base10_to_base64(ss.str());
            }
        }
    };

    int mainGenRSA(generate_rsa::PRIVATE_KEY& key, uint32_t klen_inbits);


}

#endif
