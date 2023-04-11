#ifndef KEYGEN_MGR_H_INCLUDED
#define KEYGEN_MGR_H_INCLUDED
// crypto_keygenmgr.hpp

#include "crypto_const.hpp"
#include "crypto_ecckey.hpp"
#include "qa/rsa_gen.hpp"
#include "crypto_history.hpp"
#include "crypto_key_parser.hpp"
#include "random_engine.hpp"
#include "data.hpp"
#include "crc32a.hpp"
#include "c_plus_plus_serializer.h"
#include "exclusive-lock-file.h"

#include "qa/rsa_gen.hpp"

#ifdef _WIN32
//add preprocessor directive NOMINMAX
#pragma warning ( disable : 4146 )
#endif
#include "qa/RSA-GMP/RSAGMPTest.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>


namespace cryptoAL
{
namespace keygenerator
{
	const bool SHOWDEBUG = false;

    class keygen_mgr
    {
    public:
        bool        cfg_parse_result = false;
        crypto_cfg  cfg;
        bool        verbose = false;

        keygen_mgr(const std::string& cfgfile, bool verb=false)
            :   cfg(cfgfile, verb),
                verbose(verb)
        {
			cfg_parse_result = cfg.parse();
        }

		~keygen_mgr()
		{
		}

		long long keybits8x(long long bits)
		{
			if (bits % 8 != 0)
			{
				bits += ( 8 - (bits % 8) );
			}
			return bits;
		}

		bool process_rsa(cfg_keygen_spec& spec, int max_threads)
		{
			bool r = true;

			long long primes = cfg.get_positive_value_negative_if_invalid(spec.primes);
			if (primes < 2) primes = 2;

			long long bits = cfg.get_positive_value_negative_if_invalid(spec.bits);
			if (bits < 64) bits = 64;

			long long maxusagecount = cfg.get_positive_value_negative_if_invalid(spec.maxusagecount);
			if (maxusagecount < 1) maxusagecount = 1;

			long long poolmin = cfg.get_positive_value_negative_if_invalid(spec.poolmin);
			if (poolmin < 1) poolmin = 1;

			long long poolnew = cfg.get_positive_value_negative_if_invalid(spec.poolnew);
			if (poolnew < 0) poolnew = 0;

			long long poolmax = cfg.get_positive_value_negative_if_invalid(spec.poolmax);
			if (poolmax < 1) poolmax = 1;
			if (poolmax < std::max(poolmin, poolnew)) poolmax = std::max(poolmin, poolnew);

			if (cfg.cmdparam.folder_my_private_rsa.size() == 0)
			{
				return false;
			}
			std::string local_rsa_db = cfg.cmdparam.folder_my_private_rsa + RSA_MY_PRIVATE_DB;

			bool work_todo = true;
			while (work_todo)
			{
				// scope to destroy objects
				{
					cryptoAL::db::db_mgr dbmgr(cfg);
					std::map<std::string, cryptoAL::rsa::rsa_key>* pmap_rsa = nullptr;

					// READ
					r = dbmgr.get_rsa_map(local_rsa_db, &pmap_rsa, false);
					if (r == false)
					{
						if (SHOWDEBUG) std::cout << "dbmgr.get_rsa_map() == false" << std:: endl;
						return false;
					}
					if (pmap_rsa == nullptr)
					{
						if (SHOWDEBUG) std::cout << "pmap_rsa == nullptr" << std:: endl;
						return false;
					}

					long long cnt_active = 0;
					long long cnt_new = 0;

					std::map<std::string, cryptoAL::rsa::rsa_key>& map_rsa = *pmap_rsa;
					if (SHOWDEBUG) std::cout << "rsa keys read "  << map_rsa.size() << " from " << local_rsa_db << std:: endl;
					for(auto& [keyname, k] : map_rsa)
					{
						uint32_t kbits = keybits8x(bits);

						if (k.key_size_in_bits == kbits)
						{
							if (k.primes == primes)
							{
								if (k.deleted == false)
								{
									if (k.usage_count == 0)
									{
										cnt_new++;
									}
									else if (k.usage_count < maxusagecount)
									{
										cnt_active++;
									}
									else if (k.usage_count >= maxusagecount)
									{
										// 
									}
								}
							}
						}
					}
					if (SHOWDEBUG) std::cout << "cnt new keys: " << cnt_new << std::endl;
					if (SHOWDEBUG) std::cout << "cnt active keys: " << cnt_active << std::endl;

					work_todo = false;
					long long cnt_gen_required = 0;
					long long cnt_gen_new = 0;
					long long cnt_gen_min = 0;
					if (cnt_new < poolnew)
					{
						work_todo = true;
						cnt_gen_new = poolnew - cnt_new;
					}
					if (poolmin > cnt_new + cnt_active)
					{
						work_todo = true;
						cnt_gen_min = poolmin - (cnt_new + cnt_active);
					}
					cnt_gen_required = std::max(cnt_gen_new, cnt_gen_min);

					if (cnt_gen_required > 0)
					{
						if (verbose) std::cout << "------------------------------" << std::endl;
						if (verbose) std::cout << "Required number of new RSA keys: "  << cnt_gen_required << std::endl;
						if (verbose) std::cout << "RSA key bit size:         " << bits << std::endl;
						if (verbose) std::cout << "RSA key number of primes: " << primes << std::endl;
						if (verbose) std::cout << "Number of threads:        " << max_threads << std::endl;
						if (verbose) std::cout << "------------------------------" << std::endl;

						for(long long j=0;j<cnt_gen_required;j++)
						{
							if (verbose) std::cout << "iteration: " << j + 1  <<std::endl;

							if (primes == 3)
							{
								unsigned int klen = keybits8x(bits);
								RSAGMP::Utils::TestGenerator generator;
								RSAGMP::Utils::mpzBigInteger pub;
								RSAGMP::Utils::mpzBigInteger priv;
								RSAGMP::Utils::mpzBigInteger modulus;
								bool rr = RSAGMP::get_keys_3primes(klen, &generator, max_threads, 20, pub, priv, modulus);
								if (rr)
								{
									std::string s_n(modulus.get_str());
									std::string s_e(pub.get_str());
									std::string s_d(priv.get_str());

									cryptoAL::rsa::rsa_key k;
									cryptoAL::rsa::rsa_key rkey( 3, (int)klen,
															  uint_util::base10_to_base64(s_n),
															  uint_util::base10_to_base64(s_e),
															  uint_util::base10_to_base64(s_d));

									std::string keyname = std::string("MY_RSA3KEY_") + std::to_string(klen) +
														  std::string("_") + cryptoAL::parsing::get_current_time_and_date() +
														  std::string("_") + std::to_string(j) ; // too fast = same keyname

									// Insert
									map_rsa.insert(std::make_pair(keyname,  rkey));
									dbmgr.mark_rsa_as_changed(local_rsa_db);

									if (verbose) std::cout << "key saved as: "  << keyname << " in " << local_rsa_db << std:: endl;
								}
							}
							else if (primes == 2)
							{
								unsigned int klen = keybits8x(bits);
								RSAGMP::Utils::TestGenerator generator;
								RSAGMP::Utils::mpzBigInteger pub;
								RSAGMP::Utils::mpzBigInteger priv;
								RSAGMP::Utils::mpzBigInteger modulus;
								bool rr = RSAGMP::get_keys(klen, &generator, max_threads, 20, pub, priv, modulus);
								if (rr)
								{
									std::string s_n(modulus.get_str());
									std::string s_e(pub.get_str());
									std::string s_d(priv.get_str());

									cryptoAL::rsa::rsa_key k;
									cryptoAL::rsa::rsa_key rkey( 2, (int)klen,
															  uint_util::base10_to_base64(s_n),
															  uint_util::base10_to_base64(s_e),
															  uint_util::base10_to_base64(s_d));

									std::string keyname = std::string("MY_RSA2KEY_") + std::to_string(klen) +
														  std::string("_") + cryptoAL::parsing::get_current_time_and_date() +
														  std::string("_") + std::to_string(j) ; // too fast = same keyname

									// Insert
									map_rsa.insert(std::make_pair(keyname,  rkey));
									dbmgr.mark_rsa_as_changed(local_rsa_db);

									if (verbose) std::cout << "key saved as: "  << keyname << " in " << local_rsa_db << std:: endl;
								}
							}
							else if (primes > 3)
							{
								unsigned int klen = keybits8x(bits);
								RSAGMP::Utils::TestGenerator generator;
								RSAGMP::Utils::mpzBigInteger pub;
								RSAGMP::Utils::mpzBigInteger priv;
								RSAGMP::Utils::mpzBigInteger modulus;
								bool rr = RSAGMP::get_keys_Nprimes(klen, &generator, max_threads, 20, pub, priv, modulus, primes);
								if (rr)
								{
									std::string s_n(modulus.get_str());
									std::string s_e(pub.get_str());
									std::string s_d(priv.get_str());

									cryptoAL::rsa::rsa_key k;
									cryptoAL::rsa::rsa_key rkey( primes, (int)klen,
															  uint_util::base10_to_base64(s_n),
															  uint_util::base10_to_base64(s_e),
															  uint_util::base10_to_base64(s_d));

									std::string keyname = std::string("MY_RSA") + std::to_string(primes) + std::string("KEY_") +
														  std::to_string(klen) +
														  std::string("_") + cryptoAL::parsing::get_current_time_and_date() +
														  std::string("_") + std::to_string(j) ; // too fast = same keyname

									// Insert
									map_rsa.insert(std::make_pair(keyname,  rkey));
									dbmgr.mark_rsa_as_changed(local_rsa_db);

									if (verbose) std::cout << "key saved as: "  << keyname << " in " << local_rsa_db << std:: endl;
								}
							}
						}
						
						// SAVE
						dbmgr.flush(true);

						if (cnt_gen_required > 0) if (verbose) std::cout << std:: endl;
					}
				}
			}

			return r;
		}

		bool process_ecc(cfg_keygen_spec& spec, int max_threads)
		{
			bool r = true;
			return r;
		}

		bool process(cfg_keygen_spec& spec, int max_threads)
		{
			bool r = true;
			if (spec.keytype == "rsa") return process_rsa(spec, max_threads);
			else if (spec.keytype == "ecc") return process_ecc(spec, max_threads);
			return r;
		}

		bool run(int max_threads = 32)
		{
			bool r = true;
			if (cfg_parse_result == false)
			{
				return false;
			}

			for(size_t i=0; i< cfg.keygen.vspec.size(); i++)
			{
				r = process(cfg.keygen.vspec[i], max_threads);
			}
			return r;
		}
    };

}
}
#endif