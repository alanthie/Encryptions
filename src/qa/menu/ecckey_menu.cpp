#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../../../src/crypto_ecckey.hpp"
#include "menu.h"

namespace ns_menu
{
	int main_menu::fECCKey(size_t choice)
   	{
		int r = 0;

		if (choice == 1)
        {
            std::string fileECCDOMDB;
            std::string pathDOMdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
				pathDOMdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path for ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                pathDOMdb = get_input_string();
                if (pathDOMdb == "0") pathDOMdb = "./";
                fileECCDOMDB = pathDOMdb + cryptoAL::ECC_DOMAIN_DB;
			}

			std::map< std::string, cryptoAL::ecc_domain > map_ecc_domain;

			// View
			if (file_util::fileexists(fileECCDOMDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCDOMDB, std::ios_base::in);
				infile >> bits(map_ecc_domain);
				infile.close();

				std::cout << "---------------------------" << std::endl;
				std::cout << "Domains summary in " << fileECCDOMDB << std::endl;
				std::cout << "---------------------------" << std::endl;
				std::vector<std::string> vdomname;
				int cnt=0;
				for(auto& [eccname, k] : map_ecc_domain)
				{
					std::cout << "[" << cnt+1 << "]" << eccname << std::endl;
					cnt++;
					vdomname.push_back(eccname);
				}
				std::cout << std:: endl;

				if (cnt == 0)
				{
                    std::cout << "Add ecc domain first" << std::endl;
                    r = -1;
				}

                if (r >= 0)
                {
                    std::cout << "Select a ecc domain " << 1 << "-" << std::to_string(cnt) << " (0 = largest key ) : ";
                    std::string dom;
                    dom = get_input_string();

                    long long idom = cryptoAL::parsing::str_to_ll(dom);
                    if (idom <   1) idom = 1;
                    if (idom > cnt) idom = cnt;

                    std::string dom_name = vdomname[idom-1];
                    auto& domain = map_ecc_domain[dom_name];

                    cryptoAL::ecc_key ek;
                    ek.set_domain(domain);
                    bool rr = ek.generate_private_public_key(true);

                    if (rr)
                    {
                        std::string fileECCKEYDB;
                        if (cfg_parse_result)
                        {
                            fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PRIVATE_DB;
                        }
                        else
                        {
                            std::cout << "Enter path for ecc private keys database " << cryptoAL::ECCKEY_MY_PRIVATE_DB << " (0 = same as domain) : ";
                            std::string pathecckeydb;
                            pathecckeydb = get_input_string();
                            if (pathecckeydb == "0") pathecckeydb = pathDOMdb;
                            fileECCKEYDB = pathecckeydb + cryptoAL::ECCKEY_MY_PRIVATE_DB;
                        }

                        // READ
                        std::map< std::string, cryptoAL::ecc_key > map_ecckey_private;

                        if (file_util::fileexists(fileECCKEYDB) == false)
                        {
                            std::ofstream outfile;
                            outfile.open(fileECCKEYDB, std::ios_base::out);
                            outfile.close();
                        }

                        if (file_util::fileexists(fileECCKEYDB) == true)
                        {
                            std::ifstream infile;
                            infile.open (fileECCKEYDB, std::ios_base::in);
                            infile >> bits(map_ecckey_private);
                            infile.close();
                        }
                        else
                        {
                            std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
                            r = -1;
                        }

                        if (r >= 0)
                        {
                            // backup
                            {
                                std::ofstream outfile;
                                outfile.open(fileECCKEYDB + ".bck", std::ios_base::out);
                                outfile << bits(map_ecckey_private);
                                outfile.close();
                            }

                            std::string keyname = std::string("MY_ECCKEY_") + std::to_string(domain.key_size_bits) + std::string("_") + cryptoAL::parsing::get_current_time_and_date();
                            map_ecckey_private.insert(std::make_pair(keyname, ek));

                            {
                                std::ofstream outfile;
                                outfile.open(fileECCKEYDB, std::ios_base::out);
                                outfile << bits(map_ecckey_private);
                                outfile.close();
                            }
                            std::cout << "key saved as: "  << keyname << " in " << fileECCKEYDB << std:: endl;
                        }
                    }
                    else
                    {
                        std::cerr << "ERROR generating key " << std:: endl;
                        r = -1;
                    }
                }
			}
			else
			{
				std::cerr << "ERROR no file: "  << fileECCDOMDB << std:: endl;
				r = -1;
			}
		}

        else if (choice == 2)
        {
            std::string fileECCKEYDB;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PRIVATE_DB;
			}
			else
			{
                std::cout << "Enter path for my private ecc keys db " << cryptoAL::ECCKEY_MY_PRIVATE_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_MY_PRIVATE_DB;
			}

			std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            osummary = get_input_string();
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

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
                        std::cout << "key private k   : " << k.s_k << std::endl;
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
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
					std::cout << "[e]" << kname << std:: endl;
				}
				std::cout << std:: endl;
			}
		}

		else if (choice == 3)
      	{
            // 24. EC Key: Export my public elliptic curve keys
            std::string fileECCKEYDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PRIVATE_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path for my private ecc keys db " << cryptoAL::ECCKEY_MY_PRIVATE_DB << " (0 = current directory) : ";
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_MY_PRIVATE_DB;
			}

			std::string outfile = pathdb + cryptoAL::ECCKEY_MY_PUBLIC_DB;
			std::cout << "Public ecc keys would be saved in: " << outfile << std::endl;;

			std::map< std::string, cryptoAL::ecc_key > map_ecc_private;
			std::map< std::string, cryptoAL::ecc_key > map_ecc_public;

			if (file_util::fileexists(fileECCKEYDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCKEYDB, std::ios_base::in);
				infile >> bits(map_ecc_private);
				infile.close();

				for(auto& [keyname, k] : map_ecc_private)
				{
                    cryptoAL::ecc_key key_public(k.dom, k.s_kg_x, k.s_kg_y, "");
                    map_ecc_public.insert(std::make_pair(keyname,  key_public) );
				}

				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << outfile << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [keyname, k] : map_ecc_public)
				{
				  std::cout << keyname << std:: endl;
				}
				std::cout << std:: endl;

				{
					std::ofstream out;
					out.open(outfile, std::ios_base::out);
					out << bits(map_ecc_public);
					out.close();
				}
			}
			else
			{
			  	std::cerr << "ERROR no file: " << fileECCKEYDB << std:: endl;
				r = -1;
			}
		}

	  	else if (choice == 4)
     	{
            std::string fileECCKEYDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECCKEY_MY_PUBLIC_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path for my ecc public database " << cryptoAL::ECCKEY_MY_PUBLIC_DB << " (0 = current directory) : ";
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_MY_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            osummary = get_input_string();
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

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
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
                }

				{
					std::cout << "------------------------------------------------------" << std::endl;
					std::cout << "My public keys are in file: " << fileECCKEYDB << std::endl;
					std::cout << "------------------------------------------------------" << std::endl;
					for(auto& [kname, k] : map_ecc_public)
					{
					  std::cout << "[e]" << kname << std:: endl;
					}
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
				r = -1;
            }
		}

		else if (choice == 5)
     	{
            std::string fileECCKEYDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_other_public_ecc.size()>0))
			{
				fileECCKEYDB = cfg.cmdparam.folder_other_public_ecc + cryptoAL::ECCKEY_OTHER_PUBLIC_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path of other ecc public database " << cryptoAL::ECCKEY_OTHER_PUBLIC_DB << " (0 = current directory) : ";
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCKEYDB = pathdb + cryptoAL::ECCKEY_OTHER_PUBLIC_DB;
			}

            std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            osummary = get_input_string();
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

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
                        std::cout << "key confirmed : " << k.confirmed << std::endl;
                        std::cout << "key marked for delete : " << k.deleted << std::endl;
                        std::cout << "key usage count: " << k.usage_count<< std::endl;
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
					std::cout << std:: endl;
          		}
      		}
            else
            {
                std::cerr << "ERROR no file: "  << fileECCKEYDB << std:: endl;
				r = -1;
            }
		}


        return r;
    }
}
