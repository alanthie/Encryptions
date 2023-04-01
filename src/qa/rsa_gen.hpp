#ifndef RSAGEN_H_INCLUDED
#define RSAGEN_H_INCLUDED

#include "../uint_util.hpp"
#include "../c_plus_plus_serializer.h"

namespace generate_rsa
{
    struct rsa_key
    {
        rsa_key()
        {
        };


        rsa_key(int key_size__bits, const std::string& a, const std::string& b, const std::string& c)
        {
            key_size_in_bits = key_size__bits;
            s_n = a;
            s_e = b;
            s_d = c;
        }

        uint32_t key_size_in_bits = 0;
        std::string s_n; // base 64
        std::string s_e; // base 64
        std::string s_d; // base 64 empty if public key

		// key flags
		bool 		confirmed 	= false;
		bool 		deleted 	= false;	// marked for delete
		uint32_t 	usage_count = 0;
		std::string dt_confirmed = "";

        friend std::ostream& operator<<(std::ostream &out, Bits<rsa_key & > my)
        {
            out << bits(my.t.key_size_in_bits) << bits(my.t.s_n) << bits(my.t.s_e) << bits(my.t.s_d)
            	<< bits(my.t.confirmed)
				<< bits(my.t.deleted)
				<< bits(my.t.usage_count)
				<< bits(my.t.dt_confirmed);
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<rsa_key &> my)
        {
            in >> bits(my.t.key_size_in_bits) >> bits(my.t.s_n) >> bits(my.t.s_e) >> bits(my.t.s_d)
                >> bits(my.t.confirmed)
				>> bits(my.t.deleted)
				>> bits(my.t.usage_count)
				>> bits(my.t.dt_confirmed);
            return (in);
        }

        typeuinteger get_n() { return uint_util::val(s_n);}
        typeuinteger get_e() { return uint_util::val(s_e);}
        typeuinteger get_d() { return uint_util::val(s_d);}


        typeuinteger encode(const std::string& s)
        {
            typeuinteger n = get_n();
            typeuinteger m = uint_util::val(s);
            typeuinteger r = uint_util::mod_pow(m, get_e(), n);
            return r;
        }

        std::string decode(const typeuinteger& v)
        {
            typeuinteger n = get_n();
            typeuinteger m = v;
            typeuinteger r = uint_util::mod_pow(m, get_d(), n);
            std::string  s = uint_util::to_base64(r);
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
                rkey.s_n = uint_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << e ;
                rkey.s_e = uint_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << d ;
                rkey.s_d = uint_util::base10_to_base64(ss.str());
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
                rkey.s_n = uint_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << publicExponent ;
                rkey.s_e = uint_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << privateExponent ;
                rkey.s_d = uint_util::base10_to_base64(ss.str());
            }
        }
    };

    int mainGenRSA(generate_rsa::PRIVATE_KEY& key, uint32_t klen_inbits);


}

#endif
