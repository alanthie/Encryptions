#ifndef CRYPTO_SHOW_KEY_INCLUDED
#define CRYPTO_SHOW_KEY_INCLUDED

#include "crypto_const.hpp"
#include "crypto_ecckey.hpp"
#include "qa/rsa_gen.hpp"
#include "crypto_cfg.hpp"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

// crypto_showkeys.hpp
namespace cryptoAL
{
	class report
	{
public:
	crypto_cfg cfg;

	report(const std::string& cfgfile, bool verb=false) : cfg(cfgfile, verb)
	{
	}

	~report()
	{
	}

    bool show_keys()
    {
		int r = 0;
		if (cfg.parse() == false)
			return false;

		{
			std::string fileRSADB;
			if (cfg.cmdparam.folder_my_private_rsa.size()>0)
			{
				fileRSADB = cfg.cmdparam.folder_my_private_rsa + cryptoAL::RSA_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "empty foldername cfg.cmdparam.folder_my_private_rsa  " << std::endl;
				return false;
			}

			bool onlysummary = true;

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
					std::cout 	<< "[r]" << user << " (usage_count:" << k.usage_count << ")"
								<< " (key confirmed :" << k.confirmed  << ")" << " (mark deleted :" << k.deleted  << ")"
								<< std::endl;
				}
				std::cout << "count: " << map_rsa_private.size() << std::endl;
				std::cout << std:: endl;
			}
		}

        {
            std::string fileECCKEYDB;
            if (cfg.cmdparam.folder_my_private_ecc.size()>0)
			{
				fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PRIVATE_DB;
			}
			else
			{
				std::cout << "empty foldername folder_my_private_ecc" << std::endl;
				return false;
			}

			bool onlysummary = true;

			std::map< std::string, cryptoAL::ecc_key > map_ecckey_private;

			// View
			if (file_util::fileexists(fileECCKEYDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCKEYDB, std::ios_base::in);
				infile >> bits(map_ecckey_private);
				infile.close();

                if (onlysummary == false)
                {
                    for(auto& [kname, k] : map_ecckey_private)
                    {
                        std::cout << "key name: " << kname << std::endl;
                        std::cout << "domain:   " << k.dom.name() << std::endl;
                        std::cout << "key size: " << k.dom.key_size_bits << std::endl;
                        std::cout << "key public  kG_x: " << k.s_kg_x<< std::endl;
                        std::cout << "key public  kG_y: " << k.s_kg_y<< std::endl;
                        std::cout << "key private k   : ..." << std::endl; // << k.s_k << std::endl;
                        std::cout << "key confirmed   : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count : " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
				}
			}
			else
			{
				std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
				r = -1;
			}

			if (r >= 0)
			{
				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << fileECCKEYDB << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [kname, k] : map_ecckey_private)
				{
					std::cout 	<< "[e]" << kname << " (usage_count:" << k.usage_count << ")" << " (key confirmed :" << k.confirmed  << ")"
								<< " (mark deleted :" << k.deleted  << ")" << std::endl;
				}
				std::cout << "count: " << map_ecckey_private.size() << std::endl;
				std::cout << std:: endl;
			}
		}


		//RSA Key: View other public RSA key
     	{
			std::string fileRSADB;
			if (cfg.cmdparam.folder_other_public_rsa.size()>0)
			{
				fileRSADB = cfg.cmdparam.folder_other_public_rsa + cryptoAL::RSA_OTHER_PUBLIC_DB;
			}
			else
			{
				return false;
			}
            bool onlysummary = true;

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
					std::cout << "count: " << map_RSA_private.size() << std::endl;
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "no file: "  << fileRSADB << std:: endl;
				r = -1;
            }
		}

     	{
            std::string fileECCKEYDB;
            std::string pathdb;
            if (cfg.cmdparam.folder_other_public_ecc.size()>0)
			{
				fileECCKEYDB = cfg.cmdparam.folder_other_public_ecc + cryptoAL::ECCKEY_OTHER_PUBLIC_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                return false;
			}

           	bool onlysummary = true;

			std::map< std::string, cryptoAL::ecc_key > map_ecc_public;

			// View
          	if (file_util::fileexists(fileECCKEYDB) == true)
      		{
 				std::ifstream infile;
              	infile.open (fileECCKEYDB, std::ios_base::in);
          		infile >> bits(map_ecc_public);
             	infile.close();

             	if (onlysummary == false)
                {
                    for(auto& [kname, k] : map_ecc_public)
                    {
                        std::cout << "key name: " << kname << std::endl;
                        std::cout << "domain:   " << k.dom.name() << std::endl;
                        std::cout << "key size: " << k.dom.key_size_bits << std::endl;
                        std::cout << "key public  kG_x: " << k.s_kg_x<< std::endl;
                        std::cout << "key public  kG_y: " << k.s_kg_y<< std::endl;
                        std::cout << "key private k <should be zero/empty> : " << k.s_k << std::endl;
                        std::cout << "key confirmed         : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count       : " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "Other public keys are in file: " << fileECCKEYDB << std::endl;
					std::cout << "Links to copy paste into url file when encoding message with ECC" << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [kname, k] : map_ecc_public)
					{
					  std::cout << "[e]" << kname << std:: endl;
					}
					std::cout << "count: " << map_ecc_public.size() << std::endl;
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
				r = -1;
            }

		}

		return true;
	}


	};


}
#endif
