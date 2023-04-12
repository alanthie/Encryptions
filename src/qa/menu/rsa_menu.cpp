#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../rsa_gen.hpp"
#include "menu.h"

#ifdef _WIN32
//add preprocessor directive NOMINMAX
#pragma warning ( disable : 4146 )
#endif
#include "../RSA-GMP/RSAGMPTest.h"

namespace ns_menu
{
    int system_cmd(std::string cmd)
    {
        return system(cmd.data());
    }

    long long keybits8x(long long bits)
    {
        if (bits % 8 != 0)
        {
            bits += ( 8 - (bits % 8) );
        }
        return bits;
    }

    int generate_rsa_with_openssl(typeuinteger& n, typeuinteger& e, typeuinteger& d, uint32_t klen_inbits, std::string pathopenssl)
    {
        // TODO more check
        std::string FILE = "staging_tmp_openssl_out.txt";
        std::string p = pathopenssl;
        std::string cmd1;
        std::string cmd2;
        if (p.size() > 0)
        {
            cmd1 = p + std::string("openssl.exe") + std::string(" genrsa -verbose -out key.pem ") + std::to_string(klen_inbits);
            cmd2 = p + std::string("openssl.exe") + std::string(" rsa -in key.pem -text -out ") + FILE;
        }
        else
        {
            cmd1 = std::string("openssl genrsa -out key.pem ") + std::to_string(klen_inbits);
            cmd2 = std::string("openssl rsa -in key.pem -text -out ") + FILE;
        }

        std::cout << "Will run these 2 commands on your OS, then parse and test the result keys: "<< std::endl;
        std::cout << cmd1 << std::endl;
        std::cout << cmd2 << std::endl;

		if (file_util::fileexists(FILE))
            std::remove(FILE.data());

       	system_cmd(cmd1);
        system_cmd(cmd2);

		std::string s = cryptoAL::parsing::get_block_infile(FILE, "modulus:" , "publicExponent:");
		s = cryptoAL::parsing::remove_hex_delim(s);
		n = uint_util::hex_to_uinteger(s);
		std::cout << "n = " << n << " bits: " << n.bitLength() << std::endl;

 		e = 65537;
		std::cout << "e = " << e << std::endl;

		s = cryptoAL::parsing::get_block_infile(FILE, "privateExponent:" , "prime1:");
		s = cryptoAL::parsing::remove_hex_delim(s);
		d = uint_util::hex_to_uinteger(s);
        std::cout << "d = " << d << " bits: " << d.bitLength() << std::endl;

        if (file_util::fileexists(FILE))
            std::remove(FILE.data());

         return 0;
     }


    int main_menu::fRSA(size_t choice)
    {
		int r = 0;

		if (choice == 1) // RSA Key: View my private RSA key
		{
			bool cfg_parse_result 		= this->cfg_parse_result;
			cryptoAL::crypto_cfg& cfg 	= this->cfg;

			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
                std::cout << "Enter path for my private rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			std::cout << "Only show summary (0 = true): ";
			std::string osummary;
			osummary = get_input_string();
			bool onlysummary=false;
			if (osummary == "0") onlysummary = true;

			std::map< std::string, cryptoAL::rsa::rsa_key > map_rsa_private;

			// View
			if (file_util::fileexists(fileRSADB) == true)
			{
				std::ifstream infile;
				infile.open (fileRSADB, std::ios_base::in);
				infile >> bits(map_rsa_private);
				infile.close();

				if (onlysummary == false)
				{
					for(auto& [user, k] : map_rsa_private)
					{
						std::cout << "key name: " << user << std:: endl;
						std::cout << "key size: " << k.key_size_in_bits << std:: endl;
						std::cout << "key public  n (base 64): " << k.s_n << std:: endl;
						std::cout << "key public  e (base 64): " << k.s_e << std:: endl;
						std::cout << "key private d (base 64): ..."  << std:: endl; // << k.s_d << std:: endl;
						std::cout << "key confirmed          : " << k.confirmed << std::endl;
						std::cout << "key marked for delete  : " << k.deleted << std::endl;
						std::cout << "key usage count        : " << k.usage_count<< std::endl;
						std::cout << std:: endl;
					}
					std::cout << "count: " << map_rsa_private.size() << std::endl;
				}
			}
			else
			{
				std::cerr << "no file: "  << fileRSADB << std:: endl;
				r = -1;
			}
			if (r>=0)
			{
				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << fileRSADB << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [user, k] : map_rsa_private)
				{
					std::cout << "[r]" << user << " (usage_count:" << k.usage_count << ")"  << " (key confirmed :" << k.confirmed  << ")" << std::endl;
				}
				std::cout << "count: " << map_rsa_private.size() << std::endl;
				std::cout << std:: endl;
			}
		}

		else if (choice == 2) //RSA Key: View my public RSA key (also included in the private db)
     	{
			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PUBLIC_DB;
			}
			else
			{
				std::cout << "Enter path for my rsa public database " << cryptoAL::RSA_MY_PUBLIC_DB << " (0 = current directory) : ";
				std::string pathdb;
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            osummary = get_input_string();
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			std::map< std::string, cryptoAL::rsa::rsa_key > map_RSA_private;

			// View
          	if (file_util::fileexists(fileRSADB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileRSADB, std::ios_base::in);
          		infile >> bits(map_RSA_private);
             	infile.close();

             	if (onlysummary == false)
                {
                    for(auto& [user, k] : map_RSA_private)
                    {
                        std::cout << "key name: " << user << std:: endl;
                        std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                        std::cout << "key public  n (base 64): " << k.s_n << std:: endl;
                        std::cout << "key public  e (base 64): " << k.s_e << std:: endl;
                        std::cout << "key private d (base 64): <should be zero/empty> " << k.s_d << std:: endl;
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "My public keys are in file: " << fileRSADB << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [user, k] : map_RSA_private)
					{
					  std::cout << "[r]" << user << std:: endl;
					}
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "no file: "  << fileRSADB << std:: endl;
				r = -1;
            }
		}

		else if (choice == 3) //RSA Key: View other public RSA key
     	{
			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_other_public_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_other_public_rsa + cryptoAL::RSA_OTHER_PUBLIC_DB;
			}
			else
			{
				std::cout << "Enter path of other rsa public database " << cryptoAL::RSA_OTHER_PUBLIC_DB << " (0 = current directory) : ";
				std::string pathdb;
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_OTHER_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            osummary = get_input_string();
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			std::map< std::string, cryptoAL::rsa::rsa_key > map_RSA_private;

			// View
          	if (file_util::fileexists(fileRSADB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileRSADB, std::ios_base::in);
          		infile >> bits(map_RSA_private);
             	infile.close();

             	if (onlysummary == false)
                {
                    for(auto& [user, k] : map_RSA_private)
                    {
                        std::cout << "key name: " << user << std:: endl;
                        std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                        std::cout << "key public  n (base 64): " << k.s_n << std:: endl;
                        std::cout << "key public  e (base 64): " << k.s_e << std:: endl;
                        std::cout << "key private d (base 64): <should be zero/empty> " << k.s_d << std:: endl;
                        std::cout << "key confirmed         : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count       : " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "Other public keys are in file: " << fileRSADB << std::endl;
					std::cout << "Links to copy paste into url file when encoding message with RSA" << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [user, k] : map_RSA_private)
					{
					  std::cout << "[r]" << user << std:: endl;
					}
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "no file: "  << fileRSADB << std:: endl;
				r = -1;
            }
		}

      	else if (choice == 4) //RSA Key: Export my public RSA key
      	{
			std::string fileRSADB;
			std::string pathdb;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
                pathdb = cfg.cmdparam.folder_my_private_rsa;
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path of my private rsa database to read: " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			std::string outfile = pathdb + cryptoAL::RSA_MY_PUBLIC_DB;
			std::cout << "Public rsa keys would be saved in: " << outfile << std::endl;

			std::map< std::string, cryptoAL::rsa::rsa_key > map_RSA_private;
			std::map< std::string, cryptoAL::rsa::rsa_key > map_RSA_public;

			if (file_util::fileexists(fileRSADB) == true)
			{
				std::ifstream infile;
				infile.open (fileRSADB, std::ios_base::in);
				infile >> bits(map_RSA_private);
				infile.close();

				for(auto& [keyname, k] : map_RSA_private)
				{
                    cryptoAL::rsa::rsa_key key_public;
                    key_public.key_size_in_bits = k.key_size_in_bits ;
                    key_public.s_n = k.s_n ;
                    key_public.s_e = k.s_e ;
                    key_public.s_d = "" ;

                    map_RSA_public.insert(std::make_pair(keyname,  key_public));
				}

				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << outfile << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [keyname, k] : map_RSA_public)
				{
                    std::cout << keyname << std:: endl;
				}
				std::cout << std:: endl;

				{
					std::ofstream out;
					out.open(outfile, std::ios_base::out);
					out << bits(map_RSA_public);
					out.close();
				}
			}
			else
			{
			  	std::cerr << "no file: " << fileRSADB << std:: endl;
				r = -1;
			}
		}

		else if (choice == 5) //RSA Key: Generate RSA key with OPENSSL command line (fastest)
      	{
			cryptoAL::rsa::PRIVATE_KEY key;

			std::cout << "Enter rsa key length in bits (0 = defaut = 16384): ";
			std::string snum;
			snum = get_input_string();
			long long klen = cryptoAL::parsing::str_to_ll(snum);
			if (klen==-1)
			{
                r = -1;
                return r;
			}

			if (klen == 0) klen = 16384;
			klen = keybits8x(klen);

			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path for rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			std::cout << "Enter path for OPENSSL "<< " (0 = not needed, 1 = D:\\000DEV\\Encryptions\\Exec_Windows\\binOpenSSL\\ for openssl.exe) : ";
			std::string pathopenssl;
			pathopenssl = get_input_string();
			if (pathopenssl == "0") pathopenssl = "";
			if (pathopenssl == "1") pathopenssl = "D:\\000DEV\\Encryptions\\Exec_Windows\\binOpenSSL\\";

			typeuinteger n;
			typeuinteger e;
			typeuinteger d;

			std::cout << "generating/testing key with gmp..." << std::endl;
            auto start = std::chrono::high_resolution_clock::now();

			int result = generate_rsa_with_openssl(n, e, d, (uint32_t)klen, pathopenssl);

			auto finish = std::chrono::high_resolution_clock::now();
            std::cout << "generation elapsed time: " <<  std::chrono::duration_cast<std::chrono::seconds>(finish - start).count() << " seconds"<< std:: endl;

			if (result == 0)
			{
				cryptoAL::rsa::rsa_key rkey;
				key.to_rsa_key(rkey, n, e, d, (uint32_t)klen);

				std::map< std::string, cryptoAL::rsa::rsa_key > map_RSA_private;
				if (file_util::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_RSA_private);
					infile.close();
				}

				bool test_with_gmp = true;
				bool ok = true;
				auto start1 = std::chrono::high_resolution_clock::now();

				int rr = RSAGMP::rsa_gmp_test_key(  uint_util::base64_to_base10(rkey.s_n) , uint_util::base64_to_base10(rkey.s_e),
                                                    uint_util::base64_to_base10(rkey.s_d), (uint32_t)klen);
				if (rr!=0)
				{
					ok = false;
				}

				auto finish1 = std::chrono::high_resolution_clock::now();

				std::cout << "generation elapsed time: " <<  std::chrono::duration_cast<std::chrono::seconds>(finish - start).count() << " seconds"<< std:: endl;
				std::cout << "testing elapsed time:    " <<  std::chrono::duration_cast<std::chrono::milliseconds>(finish1 - start1).count() << " milliseconds"<< std:: endl;

				if (test_with_gmp == false)
				{
					auto start1 = std::chrono::high_resolution_clock::now();
					std::cout << "Testing key..." << std:: endl;
					std::string rsa_msg = "A10";
					typeuinteger encoded;
					std::string s;
					try
					{
						encoded = rkey.encode(rsa_msg);
						s = rkey.decode(e);

						auto finish1 = std::chrono::high_resolution_clock::now();
						std::chrono::duration<double, std::milli> elapsed1 = finish1 - start1;
						std::cout << "Testing elapsed time: " << elapsed1.count() / 1000 << " sec" << std:: endl;
					}
					catch(...)
					{
						ok = false;
						std::cerr << "ERROR encoding/decoding - exception thrown" << std:: endl;
						r = -1;
					}

					if (ok)
					{
						if (rsa_msg != s)
						{
						 	 std::cerr << "ERROR encoding/decoding with key" << std:: endl;
						}
					}
				}

				if (ok)
				{
 					// backup
             		{
						std::ofstream outfile;
						outfile.open(fileRSADB + ".bck", std::ios_base::out);
						outfile << bits(map_RSA_private);
						outfile.close();
       				 }

                	std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + cryptoAL::parsing::get_current_time_and_date();
                  	map_RSA_private.insert(std::make_pair(keyname,  rkey));

					{
						std::ofstream outfile;
						outfile.open(fileRSADB, std::ios_base::out);
						outfile << bits(map_RSA_private);
						outfile.close();
         			}
                  	std::cout << "key saved as: "  << keyname << std:: endl;
				}
			}
          	else
			{
			  	std::cerr << "ERROR FAILED to generate key - retry" << std:: endl;
				r = -1;
			}
		}

   		else if (choice == 6) //RSA Key: Test RSA GMP key generator
		{
			int nt = std::thread::hardware_concurrency();
			std::cout << "using " << nt << " threads - test keys (2 primes) 1024 to 16384" << std::endl;
			RSAGMP::Utils::TestGenerator generator;
			RSAGMP::CustomTest(1024, &generator, nt);
			RSAGMP::CustomTest(2048, &generator, nt);
			RSAGMP::CustomTest(4096, &generator, nt);
			RSAGMP::CustomTest(4096*2, &generator, nt);
			RSAGMP::CustomTest(4096*4, &generator, nt);
		}
		else if (choice == 7)
		{
			int nt = std::thread::hardware_concurrency();
			std::cout << "using " << nt << " threads - test keys (3 primes) 1536 to 24576" << std::endl;
			RSAGMP::Utils::TestGenerator generator;
			RSAGMP::CustomTest3(512*3, &generator, nt);
			RSAGMP::CustomTest3(1024*3, &generator, nt);
			RSAGMP::CustomTest3(2048*3, &generator, nt);
			RSAGMP::CustomTest3(4096*3, &generator, nt);
			RSAGMP::CustomTest3(4096*6, &generator, nt);
		}

		else if (choice == 8) // RSA Key: Generate RSA key with GMP (fast)
      	{
			cryptoAL::rsa::PRIVATE_KEY key;

			std::cout << "Enter rsa key length in bits (0 = defaut = 2048): ";
			std::string snum;
			snum = get_input_string();
			long long klen = cryptoAL::parsing::str_to_ll(snum);
			if (klen==-1)
			{
                r = -1;
                return r;
			}
			if (klen == 0) klen = 2048;
			klen = keybits8x(klen);

			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path for rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			int nt = std::thread::hardware_concurrency();
			std::cout << "using " << nt << " threads" << std::endl;

			RSAGMP::Utils::TestGenerator generator;

			RSAGMP::Utils::mpzBigInteger pub;
			RSAGMP::Utils::mpzBigInteger priv;
			RSAGMP::Utils::mpzBigInteger modulus;
			bool rr = RSAGMP::get_keys((unsigned int)klen, &generator, nt, 20, pub, priv, modulus);
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

				// READ
				std::map< std::string, cryptoAL::rsa::rsa_key> map_rsa_private;

				if (file_util::fileexists(fileRSADB) == false)
				{
					std::ofstream outfile;
					outfile.open(fileRSADB, std::ios_base::out);
					outfile.close();
				}

				if (file_util::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_rsa_private);
					infile.close();
				}
				else
				{
					std::cerr << "ERROR no file: "  << fileRSADB << std:: endl;
					r = -1;
				}

				if (r >= 0)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(fileRSADB + ".bck", std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
					}

					std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + cryptoAL::parsing::get_current_time_and_date();
					map_rsa_private.insert(std::make_pair(keyname,  rkey));

					{
						std::ofstream outfile;
						outfile.open(fileRSADB, std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
					}
					std::cout << "key saved as: "  << keyname << std:: endl;
				}
			}
        }

		else if (choice == 9) // Generate RSA (3 primes) key with GMP (fast)
      	{
			cryptoAL::rsa::PRIVATE_KEY key;

			std::cout << "Enter rsa (3 primes) key length in bits (0 = defaut = 3072): ";
			std::string snum;
			snum = get_input_string();
			long long klen = cryptoAL::parsing::str_to_ll(snum);
			if (klen==-1)
			{
                r = -1;
                return r;
			}
			if (klen == 0) klen = 3072;
			klen = keybits8x(klen);

			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path for rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			int nt = std::thread::hardware_concurrency();
			std::cout << "using " << nt << " threads" << std::endl;

			RSAGMP::Utils::TestGenerator generator;

			RSAGMP::Utils::mpzBigInteger pub;
			RSAGMP::Utils::mpzBigInteger priv;
			RSAGMP::Utils::mpzBigInteger modulus;
			bool rr = RSAGMP::get_keys_3primes((unsigned int)klen, &generator, nt, 20, pub, priv, modulus);
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

				// READ
				std::map< std::string, cryptoAL::rsa::rsa_key> map_rsa_private;

				if (file_util::fileexists(fileRSADB) == false)
				{
					std::ofstream outfile;
					outfile.open(fileRSADB, std::ios_base::out);
					outfile.close();
				}

				if (file_util::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_rsa_private);
					infile.close();
				}
				else
				{
					std::cerr << "ERROR no file: "  << fileRSADB << std:: endl;
					r = -1;
				}

				if (r >= 0)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(fileRSADB + ".bck", std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
					}

					std::string keyname = std::string("MY_RSA3KEY_") + std::to_string(klen) + std::string("_") + cryptoAL::parsing::get_current_time_and_date();
					map_rsa_private.insert(std::make_pair(keyname,  rkey));

					{
						std::ofstream outfile;
						outfile.open(fileRSADB, std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
					}
					std::cout << "key saved as: "  << keyname << std:: endl;
				}
			}
		}

		else if (choice == 10) // Generate RSA (N primes) key with GMP (fast)
      	{
			cryptoAL::rsa::PRIVATE_KEY key;

			unsigned int NPRIMES = 4;
			std::cout << "Enter rsa NUMBER of primes: ";
			std::string sNPRIMES;
			sNPRIMES = get_input_string();
			long long n = cryptoAL::parsing::str_to_ll(sNPRIMES);
			if (n<=2) n=2;
			NPRIMES = (unsigned int) n;

			std::cout << "Enter rsa (" << NPRIMES <<" primes) key length in bits (0 = defaut = 4096): ";
			std::string snum;
			snum = get_input_string();
			long long klen = cryptoAL::parsing::str_to_ll(snum);
			if (klen==-1)
			{
                r = -1;
                return r;
			}
			if (klen == 0) klen = 4096;
			klen = keybits8x(klen);

			std::string fileRSADB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "Enter path for rsa database " << cryptoAL::RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
				std::string pathdb;
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
				fileRSADB = pathdb + cryptoAL::RSA_MY_PRIVATE_DB;
			}

			int nt = std::thread::hardware_concurrency();
			std::cout << "using " << nt << " threads" << std::endl;

			RSAGMP::Utils::TestGenerator generator;

			RSAGMP::Utils::mpzBigInteger pub;
			RSAGMP::Utils::mpzBigInteger priv;
			RSAGMP::Utils::mpzBigInteger modulus;
			bool rr = RSAGMP::get_keys_Nprimes((unsigned int)klen, &generator, nt, 20, pub, priv, modulus, NPRIMES);
			if (rr)
			{
				std::string s_n(modulus.get_str());
				std::string s_e(pub.get_str());
				std::string s_d(priv.get_str());

				cryptoAL::rsa::rsa_key k;
				cryptoAL::rsa::rsa_key rkey( NPRIMES, (int)klen,
										  uint_util::base10_to_base64(s_n),
										  uint_util::base10_to_base64(s_e),
										  uint_util::base10_to_base64(s_d));

				// READ
				std::map< std::string, cryptoAL::rsa::rsa_key> map_rsa_private;

				if (file_util::fileexists(fileRSADB) == false)
				{
					std::ofstream outfile;
					outfile.open(fileRSADB, std::ios_base::out);
					outfile.close();
				}

				if (file_util::fileexists(fileRSADB) == true)
				{
					std::ifstream infile;
					infile.open (fileRSADB, std::ios_base::in);
					infile >> bits(map_rsa_private);
					infile.close();
				}
				else
				{
					std::cerr << "ERROR no file: "  << fileRSADB << std:: endl;
					r = -1;
				}

				if (r >= 0)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(fileRSADB + ".bck", std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
					}

					std::string keyname = std::string("MY_RSA") + std::to_string(NPRIMES) + std::string("KEY_") + std::to_string(klen) + std::string("_") + cryptoAL::parsing::get_current_time_and_date();
					map_rsa_private.insert(std::make_pair(keyname,  rkey));

					{
						std::ofstream outfile;
						outfile.open(fileRSADB, std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
					}
					std::cout << "key saved as: "  << keyname << std:: endl;
				}
			}
        }
		return r;
	}

}
