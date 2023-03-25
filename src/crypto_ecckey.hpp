#ifndef ECCKEY_H_INCLUDED
#define ECCKEY_H_INCLUDED

#include "crypto_const.hpp"
#include "qa/mathcommon.h"
#include "crypto_key_util.hpp"
#include "crc32a.hpp"
#include "qa/ecc_point/ecc_curve.hpp"


namespace cryptoAL
{
    struct ecc_domain
    {
        ecc_domain()
        {
        }

		void create_from(const ecc_domain& d)
        {
			key_size_bits = d.key_size_bits;
            s_a = d.s_a;
            s_b = d.s_b;
            s_p = d.s_p;
            s_n = d.s_n;
            s_gx = d.s_gx;
            s_gy = d.s_gy;
            s_h  = d.s_h;

			// flags default
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

		// key flags
		bool 		confirmed 	= false;
		bool 		deleted 	= false;	// marked for deleted
		uint32_t 	usage_count = 0;
		std::string dt_confirmed = "";

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
                << bits(my.t.s_h)
			    << bits(my.t.confirmed)
				<< bits(my.t.deleted)
				<< bits(my.t.usage_count)
				<< bits(my.t.dt_confirmed);
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<ecc_domain &> my)
        {
            in 	>>  bits(my.t.key_size_bits)
                >>  bits(my.t.s_a)  >> bits(my.t.s_b) >> bits(my.t.s_p) >> bits(my.t.s_n)
                >>  bits(my.t.s_gx) >> bits(my.t.s_gy)
                >>  bits(my.t.s_h)
				>>  bits(my.t.confirmed)
				>>  bits(my.t.deleted)
				>>  bits(my.t.usage_count)
				>>  bits(my.t.dt_confirmed);
            return (in);
        }

	};

    struct ecc_key
    {
        ecc_key()
        {
        }

		void set_domain(const ecc_domain& d)
		{
			dom = d;
		}

        ecc_key(const ecc_domain& d, const std::string& kg_x, const std::string& kg_y, const std::string& k)
		{
			dom 	= d;
			s_kg_x 	= kg_x;
			s_kg_y 	= kg_y;
            s_k  	= k;
		}

        ecc_key(int nbits,
                const std::string& a, const std::string& b, const std::string& p,
                const std::string& n, const std::string& gx, const std::string& gy,
                const std::string& h, const std::string& kg_x, const std::string& kg_y,
				const std::string& k
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
            s_kg_x = kg_x;
			s_kg_y = kg_y;
            s_k  = k;
        }

        ecc_domain  dom;
        std::string s_kg_x;   	// PUBLIC KEY
		std::string s_kg_y;
        std::string s_k;    	// PRIVATE KEY - empty if from OTHER public key

		// key flags
		bool 		confirmed 	= false;
		bool 		deleted 	= false;	// marked for deleted
		uint32_t 	usage_count = 0;
		std::string dt_confirmed = "";

        friend std::ostream& operator<<(std::ostream &out, Bits<ecc_key & > my)
        {
            out << bits(my.t.dom)
                << bits(my.t.s_kg_x)
                << bits(my.t.s_kg_y)
                << bits(my.t.s_k)
                << bits(my.t.confirmed)
				<< bits(my.t.deleted)
				<< bits(my.t.usage_count)
				<< bits(my.t.dt_confirmed);
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<ecc_key &> my)
        {
            in 	>>  bits(my.t.dom)
                >>  bits(my.t.s_kg_x)
                >>  bits(my.t.s_kg_y)
                >>  bits(my.t.s_k)
                >>  bits(my.t.confirmed)
				>>  bits(my.t.deleted)
				>>  bits(my.t.usage_count)
				>>  bits(my.t.dt_confirmed);
            return (in);
        }

        typeuinteger get_a() { return key_util::val(dom.s_a);}
        typeuinteger get_b() { return key_util::val(dom.s_b);}
        typeuinteger get_p() { return key_util::val(dom.s_p);}
        typeuinteger get_n() { return key_util::val(dom.s_n);}
        typeuinteger get_gx() { return key_util::val(dom.s_gx);}
        typeuinteger get_gy() { return key_util::val(dom.s_gy);}
        typeuinteger get_kg_x() { return key_util::val(s_kg_x);}
        typeuinteger get_kg_y() { return key_util::val(s_kg_y);}
        typeuinteger get_k() { return key_util::val(s_k);}
        typeuinteger get_h() { return key_util::val(dom.s_h);}

        bool encode(const std::string& msg, const std::string& publicKey_decoder_x, const std::string& publicKey_decoder_y,
                    std::string& out_Cm_x, std::string& out_Cm_y, std::string& out_rG_x, std::string& out_rG_y, bool verb=false)
        {
            ecc_curve ecc;
			ecc.verbose = verb;
            int ir = ecc.init_curve(dom.key_size_bits,
                                    cryptoAL::key_util::base64_to_base10(dom.s_a),
                                    cryptoAL::key_util::base64_to_base10(dom.s_b),
                                    cryptoAL::key_util::base64_to_base10(dom.s_p),
                                    cryptoAL::key_util::base64_to_base10(dom.s_n),
                                    1,
                                    cryptoAL::key_util::base64_to_base10(dom.s_gx),
                                    cryptoAL::key_util::base64_to_base10(dom.s_gy));
            if (ir < 0)
            {
				std::cerr << "ERROR init ecc curve " << std::endl;
                return false;
            }

            ecc_point   out_Cm;
            ecc_point   out_rG;

            ecc_point   publicKey_decoder;
            mpz_t       privateKey_encoder;

            mpz_init_set_str(privateKey_encoder, cryptoAL::key_util::base64_to_base10(s_k).data(), 10);
            mpz_init_set_str(publicKey_decoder.x,cryptoAL::key_util::base64_to_base10(publicKey_decoder_x).data(),10);
            mpz_init_set_str(publicKey_decoder.y,cryptoAL::key_util::base64_to_base10(publicKey_decoder_y).data(),10);

            //bool encode(ecc_point& out_Cm, ecc_point& out_rG, const std::string& msg, ecc_point& publicKey, mpz_t& private_key);
            bool r = ecc.encode(out_Cm, out_rG, msg, publicKey_decoder, privateKey_encoder);
            if (r)
            {
                mpz_class cmx(out_Cm.x); out_Cm_x = cryptoAL::key_util::base10_to_base64(cmx.get_str(10));
                mpz_class cmy(out_Cm.y); out_Cm_y = cryptoAL::key_util::base10_to_base64(cmy.get_str(10));

                mpz_class rGx(out_rG.x); out_rG_x = cryptoAL::key_util::base10_to_base64(rGx.get_str(10));
                mpz_class rGy(out_rG.y); out_rG_y = cryptoAL::key_util::base10_to_base64(rGy.get_str(10));
            }
			else
			{
				std::cerr << "ERROR ecc encoding " << std::endl;
			}
            return r;
        }

        bool decode(std::string& out_msg,
                    const std::string& in_Cm_x, const std::string& in_Cm_y, const std::string& in_rG_x, const std::string& in_rG_y, bool verb=false)
        {
            ecc_curve ecc;
			ecc.verbose = verb;
            int ir = ecc.init_curve(dom.key_size_bits,
                                    cryptoAL::key_util::base64_to_base10(dom.s_a),
                                    cryptoAL::key_util::base64_to_base10(dom.s_b),
                                    cryptoAL::key_util::base64_to_base10(dom.s_p),
                                    cryptoAL::key_util::base64_to_base10(dom.s_n),
                                    1,
                                    cryptoAL::key_util::base64_to_base10(dom.s_gx),
                                    cryptoAL::key_util::base64_to_base10(dom.s_gy));
            if (ir < 0)
            {
				std::cerr << "ERROR init ecc curve " << std::endl;
                return false;
            }

            ecc_point in_Cm;
            ecc_point in_rG;

            mpz_t privateKey_decoder;

            mpz_init_set_str(privateKey_decoder,    cryptoAL::key_util::base64_to_base10(s_k).data(), 10);
            mpz_init_set_str(in_Cm.x,               cryptoAL::key_util::base64_to_base10(in_Cm_x).data(),10);
            mpz_init_set_str(in_Cm.y,               cryptoAL::key_util::base64_to_base10(in_Cm_y).data(),10);
            mpz_init_set_str(in_rG.x,               cryptoAL::key_util::base64_to_base10(in_rG_x).data(),10);
            mpz_init_set_str(in_rG.y,               cryptoAL::key_util::base64_to_base10(in_rG_y).data(),10);

            bool r = ecc.decode(in_Cm, in_rG, out_msg, privateKey_decoder);
            if (r)
            {
            }
			else
			{
				std::cerr << "ERROR ecc decoding " << std::endl;
			}
            return r;
        }

    private:
		bool compute_private_key_and_update_kG(bool verb = false)
		{
			ecc_point G;
			ecc_point rG;
			mpz_t private_key;

			mpz_init_set_str(G.x, cryptoAL::key_util::base64_to_base10(dom.s_gx).data(),10);
            mpz_init_set_str(G.y, cryptoAL::key_util::base64_to_base10(dom.s_gy).data(),10);

			mpz_init_set_str(private_key, cryptoAL::key_util::base64_to_base10(s_k).data(), 10);

			ecc_curve ecc;
			ecc.verbose = verb;
            int ir = ecc.init_curve(dom.key_size_bits,
                                    cryptoAL::key_util::base64_to_base10(dom.s_a),
                                    cryptoAL::key_util::base64_to_base10(dom.s_b),
                                    cryptoAL::key_util::base64_to_base10(dom.s_p),
                                    cryptoAL::key_util::base64_to_base10(dom.s_n),
                                    1,
                                    cryptoAL::key_util::base64_to_base10(dom.s_gx),
                                    cryptoAL::key_util::base64_to_base10(dom.s_gy));
            if (ir < 0)
            {
				std::cerr << "ERROR init ecc curve " << std::endl;
                return false;
            }

            if (verb) std::cout << "computing  rG = ecc.mult(G, private_key); " << std::endl;
			rG = ecc.mult(G, private_key);

			mpz_class kgx(rG.x); s_kg_x = cryptoAL::key_util::base10_to_base64(kgx.get_str(10));
            mpz_class kgy(rG.y); s_kg_y = cryptoAL::key_util::base10_to_base64(kgy.get_str(10));

			if (verb) std::cout << "public key kg_x:  " << s_kg_x << std::endl;
			if (verb) std::cout << "public key kg_y:  " << s_kg_y << std::endl;
			return true;
		}

    public:
		bool generate_private_public_key(bool verb = false)
		{
			long long Nbytes = 1.33 * dom.key_size_bits / 8;
			s_k = generate_base64_random_string(Nbytes);

			if (verb) std::cout << "private key:  " << s_k << std::endl;

			bool r = compute_private_key_and_update_kG(verb);
			return r;
		}

    };


}
#endif
