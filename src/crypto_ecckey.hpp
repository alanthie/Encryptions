#ifndef ECCKEY_H_INCLUDED
#define ECCKEY_H_INCLUDED

#include "crypto_const.hpp"
#include "random_engine.hpp"
#include "uint_util.hpp"
#include "crc32a.hpp"
#include "qa/ecc_point/ecc_curve.hpp"
#include "c_plus_plus_serializer.h"

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
                //dom.s_a = cryptoAL::key_util::base10_to_base64(ss.str());
                dom.s_a = uint_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << b ;
                dom.s_b = uint_util::base10_to_base64(ss.str());
            }

            {
                std::stringstream ss;
                ss << p ;
                dom.s_p = uint_util::base10_to_base64(ss.str());
            }

			{
                std::stringstream ss;
                ss << n ;
                dom.s_n = uint_util::base10_to_base64(ss.str());
            }

			{
                std::stringstream ss;
                ss << gx ;
                dom.s_gx = uint_util::base10_to_base64(ss.str());
            }


			{
                std::stringstream ss;
                ss << gy ;
                dom.s_gy = uint_util::base10_to_base64(ss.str());
            }

			{
                std::stringstream ss;
                ss << h ;
                dom.s_h = uint_util::base10_to_base64(ss.str());
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

        typeuinteger get_a() { return uint_util::val(dom.s_a);}
        typeuinteger get_b() { return uint_util::val(dom.s_b);}
        typeuinteger get_p() { return uint_util::val(dom.s_p);}
        typeuinteger get_n() { return uint_util::val(dom.s_n);}
        typeuinteger get_gx() { return uint_util::val(dom.s_gx);}
        typeuinteger get_gy() { return uint_util::val(dom.s_gy);}
        typeuinteger get_kg_x() { return uint_util::val(s_kg_x);}
        typeuinteger get_kg_y() { return uint_util::val(s_kg_y);}
        typeuinteger get_k() { return uint_util::val(s_k);}
        typeuinteger get_h() { return uint_util::val(dom.s_h);}

        bool encode(const std::string& msg, const std::string& publicKey_decoder_x, const std::string& publicKey_decoder_y,
                    std::string& out_Cm_x, std::string& out_Cm_y, std::string& out_rG_x, std::string& out_rG_y, bool verb=false)
        {
            ecc_curve ecc;
			ecc.verbose = verb;
            int ir = ecc.init_curve(dom.key_size_bits,
                                    uint_util::base64_to_base10(dom.s_a),
                                    uint_util::base64_to_base10(dom.s_b),
                                    uint_util::base64_to_base10(dom.s_p),
                                    uint_util::base64_to_base10(dom.s_n),
                                    1,
                                    uint_util::base64_to_base10(dom.s_gx),
                                    uint_util::base64_to_base10(dom.s_gy));
            if (ir < 0)
            {
				std::cerr << "ERROR init ecc curve " << std::endl;
                return false;
            }

            ecc_point   out_Cm;
            ecc_point   out_rG;

            ecc_point   publicKey_decoder;
            mpz_t       privateKey_encoder;

            mpz_init_set_str(privateKey_encoder, uint_util::base64_to_base10(s_k).data(), 10);
            mpz_init_set_str(publicKey_decoder.x,uint_util::base64_to_base10(publicKey_decoder_x).data(),10);
            mpz_init_set_str(publicKey_decoder.y,uint_util::base64_to_base10(publicKey_decoder_y).data(),10);

            //bool encode(ecc_point& out_Cm, ecc_point& out_rG, const std::string& msg, ecc_point& publicKey, mpz_t& private_key);
            bool r = ecc.encode(out_Cm, out_rG, msg, publicKey_decoder, privateKey_encoder);
            if (r)
            {
                mpz_class cmx(out_Cm.x); out_Cm_x = uint_util::base10_to_base64(cmx.get_str(10));
                mpz_class cmy(out_Cm.y); out_Cm_y = uint_util::base10_to_base64(cmy.get_str(10));

                mpz_class rGx(out_rG.x); out_rG_x = uint_util::base10_to_base64(rGx.get_str(10));
                mpz_class rGy(out_rG.y); out_rG_y = uint_util::base10_to_base64(rGy.get_str(10));
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
                                    uint_util::base64_to_base10(dom.s_a),
                                    uint_util::base64_to_base10(dom.s_b),
                                    uint_util::base64_to_base10(dom.s_p),
                                    uint_util::base64_to_base10(dom.s_n),
                                    1,
                                    uint_util::base64_to_base10(dom.s_gx),
                                    uint_util::base64_to_base10(dom.s_gy));
            if (ir < 0)
            {
				std::cerr << "ERROR init ecc curve " << std::endl;
                return false;
            }

            ecc_point in_Cm;
            ecc_point in_rG;

            mpz_t privateKey_decoder;

            mpz_init_set_str(privateKey_decoder,    uint_util::base64_to_base10(s_k).data(), 10);
            mpz_init_set_str(in_Cm.x,               uint_util::base64_to_base10(in_Cm_x).data(),10);
            mpz_init_set_str(in_Cm.y,               uint_util::base64_to_base10(in_Cm_y).data(),10);
            mpz_init_set_str(in_rG.x,               uint_util::base64_to_base10(in_rG_x).data(),10);
            mpz_init_set_str(in_rG.y,               uint_util::base64_to_base10(in_rG_y).data(),10);

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

			mpz_init_set_str(G.x, uint_util::base64_to_base10(dom.s_gx).data(),10);
            mpz_init_set_str(G.y, uint_util::base64_to_base10(dom.s_gy).data(),10);

			mpz_init_set_str(private_key, uint_util::base64_to_base10(s_k).data(), 10);

			ecc_curve ecc;
			ecc.verbose = verb;
            int ir = ecc.init_curve(dom.key_size_bits,
                                    uint_util::base64_to_base10(dom.s_a),
                                    uint_util::base64_to_base10(dom.s_b),
                                    uint_util::base64_to_base10(dom.s_p),
                                    uint_util::base64_to_base10(dom.s_n),
                                    1,
                                    uint_util::base64_to_base10(dom.s_gx),
                                    uint_util::base64_to_base10(dom.s_gy));
            if (ir < 0)
            {
				std::cerr << "ERROR init ecc curve " << std::endl;
                return false;
            }

            if (verb) std::cout << "computing  rG = ecc.mult(G, private_key); " << std::endl;
			rG = ecc.mult(G, private_key);

			mpz_class kgx(rG.x); s_kg_x = uint_util::base10_to_base64(kgx.get_str(10));
            mpz_class kgy(rG.y); s_kg_y = uint_util::base10_to_base64(kgy.get_str(10));

			if (verb) std::cout << "public key kg_x:  " << s_kg_x << std::endl;
			if (verb) std::cout << "public key kg_y:  " << s_kg_y << std::endl;
			return true;
		}

    public:
		bool generate_private_public_key(bool verb = false)
		{
			long long Nbytes = (long long) 1.33 * dom.key_size_bits / 8;
			s_k = cryptoAL::random::generate_base64_random_string(Nbytes);

			if (verb) std::cout << "private key:  " << s_k << std::endl;

			bool r = compute_private_key_and_update_kG(verb);
			return r;
		}

    };


namespace ecc
{
	[[maybe_unused]] static std::string ecc_decode_string(
									const std::string& smsg,
									ecc_key&            ek,
        							uint32_t            msg_input_size_touse,
									uint32_t&           msg_size_produced,
									bool                verbose = false)
	{
		std::string decoded_ecc_data;
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
            throw std::string("ERROR string to decode too big");
		}

		std::string out_msg;

		// parse...
		std::vector<std::string> v = parsing::split(smsg, ";");
		if (v.size() < 8)
		{
			std::cerr << "ERROR ecc_decode_string bad format - missing token " << v.size() << std::endl;
			throw std::string("ERROR ecc_decode_string bad format - missing token ");
		}

		long long vlen[4];
		vlen[0] = cryptoAL::parsing::str_to_ll(v[0]);
		vlen[1] = cryptoAL::parsing::str_to_ll(v[2]);
		vlen[2] = cryptoAL::parsing::str_to_ll(v[4]);
		vlen[3] = cryptoAL::parsing::str_to_ll(v[6]);

		std::string in_Cm_x;
		std::string in_Cm_y;
		std::string in_rG_x;
		std::string in_rG_y;

		// check len...

		if (vlen[0] > 0) in_Cm_x = v[1];
		if (vlen[1] > 0) in_Cm_y = v[3];
		if (vlen[2] > 0) in_rG_x = v[5];
		if (vlen[3] > 0) in_rG_y = v[7];

        bool r = ek.decode(	out_msg, in_Cm_x, in_Cm_y, in_rG_x, in_rG_y, verbose);
		if (r)
		{
			decoded_ecc_data = out_msg;
			if (VERBOSE_DEBUG)
			{
                std::cout << "ecc decoded data: " << decoded_ecc_data << std::endl;
			}
		}
		else
		{
            std::cerr << "ERROR ecc decoding" << std::endl;
            std::cerr << "ecc key domain " << ek.dom.name() << std::endl;
            std::cerr << "in_Cm_x " << in_Cm_x << std::endl;
            std::cerr << "in_Cm_y " << in_Cm_y << std::endl;
            std::cerr << "in_rG_x " << in_rG_x << std::endl;
            std::cerr << "in_rG_y " << in_rG_y << std::endl;
		}

        msg_size_produced = (uint32_t)decoded_ecc_data.size();
		if (msg_input_size_touse < smsg.size() )
		{
            decoded_ecc_data += smsg.substr(msg_input_size_touse);
            std::cout << "ecc recursive decoded data: " << decoded_ecc_data << std::endl;
        }
		return decoded_ecc_data;
	}

	[[maybe_unused]] static std::string ecc_decode_full_string(	const std::string& smsg, ecc_key& ek,
                                                                uint32_t& msg_size_produced, bool verbose=false)
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
                std::cerr << "ERROR decoding ECC invalid length r_remaining.size() < 10 + v_size " << r_remaining.size() << " " << 10 + v_size << std::endl;
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
					std::string t = ecc_decode_string(v[i], ek, v[i].size(), t_msg_size_produced, verbose);

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
				sz += vr[i].size();
			}
			msg_size_produced = sz;
			if (cryptoAL::VERBOSE_DEBUG) std::cout << "output size: " << sz << std::endl;
		}
		return r;
	}

	[[maybe_unused]] static std::string ecc_encode_string(
                                    const std::string&  smsg,
									ecc_key&            ek,
									const std::string&  public_key_of_decoder_x,
									const std::string&  public_key_of_decoder_y,
                                    uint32_t&           msg_input_size_used,
									uint32_t&           msg_size_produced,
                                    bool                SELF_TEST,
                                    bool                verbose = false)
	{
		std::string encoded_ecc_data;

		// smsg maybe less or bigger than ecc capacity
		std::string msg_to_encrypt;

		//	MSG_BYTES_MAX = bits_len/8;
		//	MSG_BYTES_MAX -= 1;             // space to find a valid message on curve x+0, 1,...255 - 50% of x are on curve
		//	MSG_BYTES_PAD = 1;
		uint32_t key_len_bytes = ek.dom.key_size_bits / 8;
		key_len_bytes--;

		if (key_len_bytes < smsg.size())
		{
			msg_to_encrypt = smsg.substr(0, key_len_bytes);
		}
		else
		{
			msg_to_encrypt = smsg;
		}
		msg_input_size_used = (uint32_t)msg_to_encrypt.size();

		{
			std::string out_Cm_x;
			std::string out_Cm_y;
			std::string out_rG_x;
			std::string out_rG_y;

			bool r = ek.encode(	msg_to_encrypt, public_key_of_decoder_x, public_key_of_decoder_y, out_Cm_x, out_Cm_y, out_rG_x, out_rG_y, verbose);

			if (r)
			{
				encoded_ecc_data  = std::to_string(out_Cm_x.size()) + ";" + out_Cm_x + ";";
				encoded_ecc_data += std::to_string(out_Cm_y.size()) + ";" + out_Cm_y + ";";
				encoded_ecc_data += std::to_string(out_rG_x.size()) + ";" + out_rG_x + ";";
				encoded_ecc_data += std::to_string(out_rG_y.size()) + ";" + out_rG_y + ";";

				if (VERBOSE_DEBUG)
				{
                    std::cout << "ecc encoded data [Cm+rG]: " << encoded_ecc_data << std::endl;
                    std::cout << "ecc encoded data [Cm+rG] size: " << encoded_ecc_data.size() << std::endl;
				}
			}

			if (SELF_TEST)
			{
			}
		}

		msg_size_produced = (uint32_t)encoded_ecc_data.size() ;
		if (msg_to_encrypt.size() < smsg.size())
		{
			encoded_ecc_data += smsg.substr(msg_to_encrypt.size());
			if (VERBOSE_DEBUG)
            {
                std::cout << "ecc recursive encoded data: " << encoded_ecc_data << std::endl;
                std::cout << "ecc recursive encoded data size: " << encoded_ecc_data.size() << std::endl;
            }
		}
		return encoded_ecc_data;
	}

	[[maybe_unused]] static std::string ecc_encode_full_string(
                                        const std::string&  smsg,
										ecc_key&            ek,
										const std::string&  public_key_of_decoder_x,
                                        const std::string&  public_key_of_decoder_y,
										uint32_t&           msg_size_produced,
										bool                SELF_TEST,
										bool                verbose=false)
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

			std::string t = ecc_encode_string(	r_remaining,
                                                ek,
                                                public_key_of_decoder_x,
                                                public_key_of_decoder_y,
												t_msg_input_size_used,
												t_msg_size_produced,
												SELF_TEST,
												verbose);

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
		msg_size_produced = r.size();

		if (cryptoAL::VERBOSE_DEBUG) std::cout << current_encoded_msg_len << "-" << msg_size_produced <<std::endl;
		return r;
	}

}


}
#endif
