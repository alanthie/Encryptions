#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../../../src/c_plus_plus_serializer.h"
#include "menu.h"
#include "../SystemProperties.hpp"

namespace ns_menu
{
/*
	"Tools",
	{
		{"HEX file dump", 	1},
		{"SHA256 of a file",2},
		{"Hardware info",3},
		{"Summary of binary.dat.*",4}
		{"Summary of WBEAS keys",5}
	}
*/
	int main_menu::fTOOLS(size_t choice)
   	{
        int r = 0;
        if (choice == 1)
        {
            std::cout << "HEX(file, position, keysize)" << std::endl;
            std::cout << "Enter filename: ";
            std::string sfile;
            sfile = get_input_string();

            std::cout << "Enter position: ";
            std::string spos;
            spos = get_input_string();
            long long pos = cryptoAL::parsing::str_to_ll(spos);

            std::cout << "Enter keysize: ";
            std::string skeysize;
            skeysize = get_input_string();
            long long keysize = cryptoAL::parsing::str_to_ll(skeysize);

            std::string rr = file_util::HEX(sfile, pos, keysize);
            std::cout << "HEX(" << sfile << "," << pos << "," << keysize << ") = " << rr << std::endl;
            std::cout << std::endl;
        }
        else if (choice == 2)
        {
            std::cout << "Enter filename: ";
            std::string sfile;
            sfile = get_input_string();

            std::string rr = file_util::file_checksum(sfile);
            std::cout << "SHA(" << sfile << ") = " << rr << std::endl;
            std::cout << std::endl;
        }
		else if (choice == 3)
        {
			System::Properties pr;
			std::cout << "CPUModel:" << pr.CPUModel() << std::endl;
			std::cout << "CPUArchitecture:" << pr.CPUArchitecture()<< std::endl;
			std::cout << "OSName:" << pr.OSName()<< std::endl;
			std::cout << "OSVersion:" << pr.OSVersion()<< std::endl;
			std::cout << "RAMTotal:" << pr.RAMTotal()<< std::endl;
			std::cout << "GPUName:" << pr.GPUName()<< std::endl;
			std::cout << "GPUVendor:" << pr.GPUVendor()<< std::endl;
		}
		else if (choice == 4)
        {
			std::string pathkey;
			if ((cfg_parse_result) && (cfg.cmdparam.folder_local.size()>0))
			{
				pathkey = cfg.cmdparam.folder_local;
				std::cout << "Folder where binary.dat.* file will be read [using local folder in config]:" << pathkey << std::endl;
			}
			else
			{
				std::cout << "Enter path where binary.dat.* files are" << " (0 = current directory) : ";
				pathkey = get_input_string();
				if (pathkey == "0") pathkey = "./";
			}

			std::cout << "--------------------------------------------------" << std::endl;
			std::cout << "Summary of binary.dat.*" << std::endl;
			std::cout << "Folder: " << pathkey << std::endl;
			std::cout << "--------------------------------------------------" << std::endl;
			std::vector<std::string> vbin = file_util::get_directory_files(pathkey, "binary.dat.", true);
			std::sort(vbin.begin(),vbin.end());
			std::string chk;
			std::string all;
			for(size_t i = 0; i < vbin.size(); i++)
			{
				chk = file_util::file_checksum(pathkey + "/" + vbin[i]);
				std::cout << "[" << i+1 << "] File: " << vbin[i] << " SHA: " << chk << std::endl;
				all+=chk;
			}

			{
				SHA256 sha;
				sha.update(reinterpret_cast<const uint8_t*> (all.data()), all.size() );
				uint8_t* digest = sha.digest();
				std::string s = SHA256::toString(digest);
				delete[] digest;

				std::cout << "--------------------------------------------------" << std::endl;
				std::cout << "Count: " << vbin.size() << std::endl;
				std::cout << "Overall SHA: " << s << std::endl<< std::endl;
			}
		}
		else if (choice == 5)
        {
			std::string pathdb;
			if ((cfg_parse_result) && (cfg.cmdparam.wbaes_my_private_path.size()>0))
			{
				pathdb = cfg.cmdparam.wbaes_my_private_path;
				std::cout << "Folder where key tables (*.tbl) will be read [using wbaes_my_private_path in config]: " << pathdb << std::endl;
			}
			else
			{
				std::cout << "Enter path where key tables (*.tbl) will be read " << " (0 = current directory) : ";
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
			}

			std::cout << "--------------------------------------------------" << std::endl;
			std::cout << "Summary of *.tbl" << std::endl;
			std::cout << "Folder: " << pathdb << std::endl;
			std::cout << "--------------------------------------------------" << std::endl;
			std::vector<std::string> vbin = file_util::get_directory_files(pathdb, ".tbl", false);
			std::sort(vbin.begin(),vbin.end());
			std::string chk;
			std::string all;
			for(size_t i = 0; i < vbin.size(); i++)
			{
				chk = file_util::file_checksum(pathdb + "/" + vbin[i]);
				std::cout << "[" << i+1 << "] File: " << vbin[i] << " SHA: " << chk << std::endl;
				all+=chk;
			}

			{
				SHA256 sha;
				sha.update(reinterpret_cast<const uint8_t*> (all.data()), all.size() );
				uint8_t* digest = sha.digest();
				std::string s = SHA256::toString(digest);
				delete[] digest;

				std::cout << "--------------------------------------------------" << std::endl;
				std::cout << "Count: " << vbin.size() << std::endl;
				std::cout << "Overall SHA: " << s << std::endl<< std::endl;
			}
		}
		else if (choice == 6)
        {
			std::string pathdb;
			if ((cfg_parse_result) && (cfg.cmdparam.wbaes_my_private_path.size()>0))
			{
				pathdb = cfg.cmdparam.wbaes_my_private_path;
				std::cout << "Folder where wbaes key tables(*.tbl) will be read [using wbaes_my_private_path in config]: " << pathdb << std::endl;
			}
			else
			{
				std::cout << "Enter path where wbaes key tables (*.tbl) will be read " << " (0 = current directory) : ";
				pathdb = get_input_string();
				if (pathdb == "0") pathdb = "./";
			}

			std::cout << "--------------------------------------------------" << std::endl;
			std::cout << "Summary of wabeas keys" << std::endl;
			std::cout << "Folder: " << pathdb << std::endl;
			std::cout << "--------------------------------------------------" << std::endl;
			std::vector<std::string> vbin = file_util::get_directory_files(pathdb, "_tyboxes.tbl", false);
			std::sort(vbin.begin(),vbin.end());
			std::vector<std::string> vkey;
			for(size_t i = 0; i < vbin.size(); i++)
			{
				vkey.push_back(vbin[i].substr(0, vbin[i].find("_tyboxes.tbl")));
			}

			std::string all;
			for(size_t i = 0; i < vkey.size(); i++)
			{
				std::cout << "[" << i+1 << "] Key: " << vkey[i] << std::endl;
				all+=vkey[i];
			}

			{
				SHA256 sha;
				sha.update(reinterpret_cast<const uint8_t*> (all.data()), all.size() );
				uint8_t* digest = sha.digest();
				std::string s = SHA256::toString(digest);
				delete[] digest;

				std::cout << "--------------------------------------------------" << std::endl;
				std::cout << "Count: " << vkey.size() << std::endl;
				std::cout << "Overall keys SHA: " << s << std::endl<< std::endl;
			}
		}

        return r;
	}
}

