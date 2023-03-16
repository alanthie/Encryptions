#ifndef ECCKEY_H_INCLUDED
#define ECCKEY_H_INCLUDED

#include "qa/mathcommon.h"
#include "base_const.hpp"
#include "crypto_key_util.hpp"
#include "crc32a.hpp"

namespace cryptoAL
{
    struct ecc_domain
    {
        ecc_domain()
        {
        }
		
        // elliptic curve domain parameters:
		int key_size_bits = 0;
		
		// base 64 string
        std::string s_a;
        std::string s_b;
        std::string s_p;    // prime modulus
        std::string s_n;    // order cardinality
        std::string s_gx;
        std::string s_gy;
        std::string s_h;    // factor  
		
		std::string name()
		{		
			std::string t = std::to_string(key_size_bits) + s_a + s_b + s_p + s_n + s_gx + s_gy + s_h;

			SHA256 sha;
			sha.update(reinterpret_cast<const uint8_t*> (t.data()), t.size() );
			uint8_t* digest = sha.digest();
			std::string checksum = SHA256::toString(digest);

			std::string s = std::to_string(key_size_bits) + "_" +  checksum;
			return s;
		}
		
		ecc_domain(	int nbits, 
					const std::string& a, const std::string& b, const std::string& p,
					const std::string& n, const std::string& gx, const std::string& gy,
					const std::string& h)
		{
		    key_size_bits = nbits;
            s_a = a;
            s_b = b;
            s_p = p;
            s_n = n;
            s_gx = gx;
            s_gy = gy;
            s_h  = h;
		}

        static void to_ecc_domain(	ecc_domain& dom, uint32_t keysize_in_bits,
							const typeuinteger& a, const typeuinteger& b,  const typeuinteger& p, 
							const typeuinteger& n, const typeuinteger& gx, const typeuinteger& gy, const typeuinteger& h)
        {
            dom.key_size_bits = keysize_in_bits;
            {
                std::stringstream ss;
                ss << a ; // base 10
                dom.s_a = cryptoAL::key_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << b ;
                dom.s_b = cryptoAL::key_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << p ;
                dom.s_p = cryptoAL::key_util::base10_to_base64(ss.str());
            }
			
			{
                std::stringstream ss;
                ss << n ;
                dom.s_n = cryptoAL::key_util::base10_to_base64(ss.str());
            }
			
			{
                std::stringstream ss;
                ss << gx ;
                dom.s_gx = cryptoAL::key_util::base10_to_base64(ss.str());
            }
			
			
			{
                std::stringstream ss;
                ss << gy ;
                dom.s_gy = cryptoAL::key_util::base10_to_base64(ss.str());
            }
			
			{
                std::stringstream ss;
                ss << h ;
                dom.s_h = cryptoAL::key_util::base10_to_base64(ss.str());
            }
        }
		
		friend std::ostream& operator<<(std::ostream &out, Bits<ecc_domain & > my)
        {
            out << bits(my.t.key_size_bits) 
                << bits(my.t.s_a) << bits(my.t.s_b) << bits(my.t.s_p) << bits(my.t.s_n) 
                << bits(my.t.s_gx) << bits(my.t.s_gy)
                << bits(my.t.s_h) ;
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<ecc_domain &> my)
        {
            in 	>>  bits(my.t.key_size_bits) 
                >>  bits(my.t.s_a)  >> bits(my.t.s_b) >> bits(my.t.s_p) >> bits(my.t.s_n) 
                >>  bits(my.t.s_gx) >> bits(my.t.s_gy)
                >>  bits(my.t.s_h);
            return (in);
        }

	};
		
    struct ecc_key
    {
        ecc_key()
        {
        }

        ecc_key(const ecc_domain& d, const std::string& kg, const std::string& k)
		{
			dom = d;
			s_kg = kg;
            s_k  = k;
		}
				
        ecc_key(int nbits, 
                const std::string& a, const std::string& b, const std::string& p,
                const std::string& n, const std::string& gx, const std::string& gy,
                const std::string& h, const std::string& kg, const std::string& k
                )
        {
            dom.key_size_bits = nbits;
            dom.s_a = a;
            dom.s_b = b;
            dom.s_p = p;
            dom.s_n = n;
            dom.s_gx = gx;
            dom.s_gy = gy;
            dom.s_h  = h;
            s_kg = kg;
            s_k  = k;
        }
  
        ecc_domain dom;
        std::string s_kg;   // public
        std::string s_k;    // private - empty if public key

        friend std::ostream& operator<<(std::ostream &out, Bits<ecc_key & > my)
        {
            out << bits(my.t.dom) 
                << bits(my.t.s_kg) 
                << bits(my.t.s_k) ;
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<ecc_key &> my)
        {
            in 	>>  bits(my.t.dom) 
                >>  bits(my.t.s_kg) 
                >>  bits(my.t.s_k);
            return (in);
        }


        typeuinteger get_a() { return key_util::val(dom.s_a);}
        typeuinteger get_b() { return key_util::val(dom.s_b);}
        typeuinteger get_p() { return key_util::val(dom.s_p);}
        typeuinteger get_n() { return key_util::val(dom.s_n);}
        typeuinteger get_gx() { return key_util::val(dom.s_gx);}
        typeuinteger get_gy() { return key_util::val(dom.s_gy);}
        typeuinteger get_kg() { return key_util::val(s_kg);}
        typeuinteger get_k() { return key_util::val(s_k);}
        typeuinteger get_h() { return key_util::val(dom.s_h);}		

        typeuinteger encode(const std::string& s)
        {
			typeuinteger r = 0;
            return r;
        }

        std::string decode(const typeuinteger& v)
        {
            std::string r = "0";
            return r;
        }


    };

    
}
#endif
