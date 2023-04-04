#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../../../src/crypto_history.hpp"
#include "menu.h"

namespace ns_menu
{
	int main_menu::fHH(int choice)
   	{
		int r = 0;

		if (choice == 1)
      	{
      		std::string fileHistoDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB;
			}
			else
			{
                std::cout << "Enter path of encode history database " << cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileHistoDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB;
			}

			if (file_util::fileexists(fileHistoDB) == true)
			{
				cryptoAL::show_history_key(fileHistoDB);
			}
			else
			{
				std::cerr << "ERROR no file: " << fileHistoDB << std:: endl;
				r = -1;
			}
        }

        else if (choice == 2)
      	{
            std::string fileHistoDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path of decode history database " << cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileHistoDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
			}

			if (file_util::fileexists(fileHistoDB) == true)
			{
				cryptoAL::show_history_key(fileHistoDB);
			}
			else
			{
				std::cerr << "ERROR no file: " << fileHistoDB << std:: endl;
				r = -1;
			}
        }

		else if (choice == 3)
      	{
            //std::cout << "16. Histo: Export public decode history hashes" << std::endl;
            std::string fileHistoPrivateDB;
            std::string fileHistoPublicDB;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoPrivateDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
				fileHistoPublicDB  = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PUBLIC_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path of private decode history database " << cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileHistoPrivateDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
                fileHistoPublicDB  = pathdb + cryptoAL::HHKEY_MY_PUBLIC_DECODE_DB;
            }

			if (file_util::fileexists(fileHistoPrivateDB) == true)
			{
				bool rr = cryptoAL::export_public_history_key(fileHistoPrivateDB, fileHistoPublicDB);
				if (rr==false)
				{
                    std::cerr << "ERROR export FAILED" << std:: endl;
					r = -1;
				}
				else
				{
                    std::cout << "export OK " << fileHistoPublicDB <<  std:: endl;
				}
			}
			else
			{
				std::cerr << "ERROR no file: " << fileHistoPrivateDB << std:: endl;
				r = -1;
			}
        }
		else if (choice == 4)
      	{
			// Conirming:
			// 	Received HHKEY_OTHER_PUBLIC_DECODE_DB
			// 	Update HHKEY_MY_PRIVATE_ENCODE_DB
			std::string fileHistoPrivateEncodeDB;
            std::string importfile;

			if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_hh.size()>0))
			{
				fileHistoPrivateEncodeDB = cfg.cmdparam.folder_my_private_hh + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path of encode history database " << cryptoAL::HHKEY_MY_PRIVATE_ENCODE_DB << " (0 = current directory) : ";
                std::string pathdb;
                pathdb = get_input_string();
                if (pathdb == "0") pathdb = "./";
                fileHistoPrivateEncodeDB = pathdb + cryptoAL::HHKEY_MY_PRIVATE_DECODE_DB;
            }

            if ((cfg_parse_result) && (cfg.cmdparam.folder_other_public_hh.size()>0))
			{
				importfile = cfg.cmdparam.folder_other_public_hh + cryptoAL::HHKEY_OTHER_PUBLIC_DECODE_DB;
			}
			else
			{
                std::cout << "Enter path to read received hh (" + cryptoAL::HHKEY_OTHER_PUBLIC_DECODE_DB + ")" << " (0 = current directory) : ";
                std::string pathreaddb;
                pathreaddb = get_input_string();
                if (pathreaddb == "0") pathreaddb = "./";
                importfile = pathreaddb + cryptoAL::HHKEY_OTHER_PUBLIC_DECODE_DB;
            }

			if (file_util::fileexists(fileHistoPrivateEncodeDB) == true)
			{
				if (file_util::fileexists(importfile) == true)
				{
					uint32_t cnt;
					uint32_t n;
					bool rr = cryptoAL::confirm_history_key(fileHistoPrivateEncodeDB, importfile, cnt, n);
					if (rr==false)
					{
						std::cerr << "ERROR confirm FAILED" << std:: endl;
						r = -1;
					}
					else
					{
						std::cout << "number of new confirm: " << cnt << ", number of hashes: " << n << std:: endl;
					}
				}
				else
				{
					std::cerr << "ERROR no file: " << importfile << std:: endl;
					r = -1;

				}
            }
			else
			{
				std::cerr << "ERROR no file: " << fileHistoPrivateEncodeDB << std:: endl;
				r = -1;
			}
        }

        return r;
    }
}

