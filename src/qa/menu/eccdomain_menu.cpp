#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../../../src/ecc_util.hpp"
#include "../../../src/crypto_ecckey.hpp"
#include "menu.h"

namespace ns_menu
{
	int main_menu::fECCDomain(size_t choice)
   	{
		int r = 0;

		if (choice == 1)
      	{
			std::cout << "Enter ecc text file (ecgen output) to parse: ";
			std::string eccfile;
			eccfile = get_input_string();

			std::string fileECCDOMDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
			}
			else
			{
                std::cout << "Enter path for ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
			}

			if (file_util::fileexists(eccfile) == true)
			{
                int klen = 0;
				typeuinteger a; typeuinteger b; typeuinteger p;
				typeuinteger n; typeuinteger gx; typeuinteger gy;
				typeuinteger h;

				bool rr = ecc_util::parse_ecc_domain(eccfile, klen, a, b, p, n, gx, gy, h);
				if (rr)
				{
                    cryptoAL::ecc_domain dom;
                    cryptoAL::ecc_domain::to_ecc_domain(dom, klen, a, b, p, n, gx, gy, h);

					// READ
					std::map< std::string, cryptoAL::ecc_domain > map_ecc_domain;

					if (file_util::fileexists(fileECCDOMDB) == false)
					{
						std::ofstream outfile;
						outfile.open(fileECCDOMDB, std::ios_base::out);
						outfile.close();
					}

					if (file_util::fileexists(fileECCDOMDB) == true)
					{
						std::ifstream infile;
						infile.open (fileECCDOMDB, std::ios_base::in);
						infile >> bits(map_ecc_domain);
						infile.close();
					}
					else
					{
						std::cerr << "ERROR no file: "  << fileECCDOMDB << std:: endl;
						r = -1;
					}

					if (r >= 0)
					{
						// backup
						{
							std::ofstream outfile;
							outfile.open(fileECCDOMDB + ".bck", std::ios_base::out);
							outfile << bits(map_ecc_domain);
							outfile.close();
						}

						//std::string keyname = std::string("MY_RSAKEY_") + std::to_string(klen) + std::string("_") + cryptoAL::get_current_time_and_date();
						map_ecc_domain.insert(std::make_pair(dom.name(), dom) );

						{
							std::ofstream outfile;
							outfile.open(fileECCDOMDB, std::ios_base::out);
							outfile << bits(map_ecc_domain);
							outfile.close();
						}

						std::cout << "elliptic curve domain save as: " << dom.name() << std:: endl;
					}
				}
				else
                {
                    std::cerr << "ERROR parse error" << std:: endl;
                    r = -1;
                }
			}
			else
			{
				std::cerr << "ERROR no file: " << eccfile << std:: endl;
				r = -1;
			}
        }

        else if (choice == 2)
        {
            std::cout << "Example: launch this command in Linux for  512 ECC bits key: ./ecgen --fp -v -m 2g  -u -p -r 512" << std::endl;
            std::cout << "Example: launch this command in Linux for 1024 ECC bits key: ./ecgen --fp -v -m 16g -u -p -r 1024" << std::endl;
            std::cout << "Example: launch this command in Linux for 2048 ECC bits key: ./ecgen --fp -v -m 32g -u -p -r 2048" << std::endl;
            std::cout << "Save the output in a text file then do [Import an elliptic curve domain from text file]" << std::endl;
            std::cout << "Enter 0 to continue" << std::endl;

            std::string fileECCDOMDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
			}
			else
			{
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
            }
        }

        else if (choice == 3)
        {
            std::string fileECCDOMDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
			}
			else
			{
                std::cout << "Enter path for ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
			}

			std::cout << "Only show summary (0 = true): ";
            std::string osummary;
            osummary = get_input_string();
            bool onlysummary=false;
            if (osummary == "0") onlysummary = true;

			std::map< std::string, cryptoAL::ecc_domain > map_ecc_domain;

			// View
			if (file_util::fileexists(fileECCDOMDB) == true)
			{
				std::ifstream infile;
				infile.open (fileECCDOMDB, std::ios_base::in);
				infile >> bits(map_ecc_domain);
				infile.close();

                if (onlysummary == false)
                {
                    for(auto& [eccname, k] : map_ecc_domain)
                    {
                        std::cout << "ecc name: " << eccname << std:: endl;
                        std::cout << "ecc size: " << k.key_size_bits << std:: endl;
                        std::cout << "ecc a : " << k.s_a << std:: endl;
                        std::cout << "ecc b : " << k.s_b << std:: endl;
                        std::cout << "ecc p : " << k.s_p << std:: endl;
                        std::cout << "ecc n : " << k.s_n<< std:: endl;
                        std::cout << "ecc gx : " << k.s_gx << std:: endl;
                        std::cout << "ecc gy : " << k.s_gy << std:: endl;
                        std::cout << "ecc h : " << k.s_h << std:: endl;
                        std::cout << "ecc confirmed : " << k.confirmed << std::endl;
                        std::cout << "ecc marked for delete : " << k.deleted << std::endl;
                        std::cout << "ecc usage count: " << k.usage_count<< std::endl;
                        std::cout << std:: endl;
                    }
				}
			}
			else
			{
				std::cerr << "no file: "  << fileECCDOMDB << std:: endl;
				r = -1;
			}

			if (r>=0)
			{
				std::cout << "---------------------------" << std::endl;
				std::cout << "Summary of " << fileECCDOMDB << std::endl;
				std::cout << "---------------------------" << std::endl;
				for(auto& [eccname, k] : map_ecc_domain)
				{
					std::cout << eccname << std:: endl;
				}
				std::cout << std:: endl;
			}
		}

		else if (choice == 4)
        {
            std::string fileECCDOMDB;
            std::string pathdb;
            if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_ecc.size()>0))
			{
				fileECCDOMDB = cfg.cmdparam.folder_my_private_ecc + cryptoAL::ECC_DOMAIN_DB;
				pathdb = cfg.cmdparam.folder_my_private_ecc;
			}
			else
			{
                std::cout << "Enter path of your ecc domain database " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileECCDOMDB = pathdb + cryptoAL::ECC_DOMAIN_DB;
			}

			std::string fileECCDOMOTHERDB;
			std::string pathotherdb;
// 			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_other_public_ecc.size()>0))
//			{
//				fileECCDOMOTHERDB = cfg.cmdparam.folder_my_other_public_ecc + cryptoAL::ECC_DOMAIN_DB;
//				pathotherdb = cfg.cmdparam.folder_my_other_public_ecc;
//			}
//			else
			{
				std::cout << "Enter path of other ecc domain database to import " << cryptoAL::ECC_DOMAIN_DB << " (0 = current directory) : ";
				std::string pathotherdb;
				pathotherdb = get_input_string();
				if (pathotherdb == "0") pathotherdb = "./";
				std::string fileECCDOMOTHERDB = pathotherdb + cryptoAL::ECC_DOMAIN_DB;
			}

            if (fileECCDOMDB == fileECCDOMOTHERDB)
            {
                std::cerr << "ERROR paths should be different" << std::endl;
                r = -1;
            }
            if (file_util::fileexists(fileECCDOMDB) == false)
			{
                std::cerr << "ERROR no file: " << fileECCDOMDB << std::endl;
                r = -1;
			}
            if (file_util::fileexists(fileECCDOMOTHERDB) == false)
			{
                std::cerr << "ERROR no file: " << fileECCDOMOTHERDB << std::endl;
                r = -1;
			}

			if (r >= 0)
			{
				std::map< std::string, cryptoAL::ecc_domain > map_ecc_my_domain;
				std::map< std::string, cryptoAL::ecc_domain > map_ecc_other_domain;

				{
					std::ifstream infile;
					infile.open (fileECCDOMDB, std::ios_base::in);
					infile >> bits(map_ecc_my_domain);
					infile.close();
				}

				{
					std::ifstream infile;
					infile.open (fileECCDOMOTHERDB, std::ios_base::in);
					infile >> bits(map_ecc_other_domain);
					infile.close();
				}

				// backup
				{
					std::ofstream outfile;
					outfile.open(fileECCDOMDB + ".bck", std::ios_base::out);
					outfile << bits(map_ecc_my_domain);
					outfile.close();
				}

				int cnt = 0;
				for(auto& [eccname, k] : map_ecc_other_domain)
				{
					if (map_ecc_my_domain.find(eccname) == map_ecc_my_domain.end())
					{
						map_ecc_my_domain.insert(std::make_pair(eccname, k) );

						cnt++;
						std::cout << "---------------" << eccname << std:: endl;
						std::cout << "adding domain: " << eccname << std:: endl;
						std::cout << "       prime : " << k.s_p << std:: endl;
						std::cout << "---------------" << eccname << std:: endl;
					}
				}

				if (cnt == 0)
				{
					std::cout << "no new domain to import" << std:: endl;
					r = -1;
				}
				else
				{
					std::ofstream outfile;
					outfile.open(fileECCDOMDB, std::ios_base::out);
					outfile << bits(map_ecc_my_domain);
					outfile.close();
				}
			}
        }


        return r;
    }
}
