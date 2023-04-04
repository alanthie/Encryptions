#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../aes-whitebox/aes_whitebox.hpp"
#include "../aes-whitebox/aes_whitebox_compiler.hpp"
#include "../../../src/c_plus_plus_serializer.h"
#include "menu.h"

namespace ns_menu
{
	int main_menu::fWBAES(int choice)
   	{
        int r = 0;
        if (choice == 1)
        {
			if (true)
			{
			    std::cout << "Select one 1=AES512, 2=AES1024, 3=AES2048, 4=AES4096, 5=AES8192, 6=AES16384, 7=AES32768 ";
				std::string spos;
				std::cin >> spos;
				long long pos = cryptoAL::parsing::str_to_ll(spos);
				if (pos<1) pos = 1;
				if (pos>7) pos = 7;

				std::string aes;
				if      (pos==1) aes = "aes512";
				else if (pos==2) aes = "aes1024";
				else if (pos==3) aes = "aes2048";
				else if (pos==4) aes = "aes4096";
				else if (pos==5) aes = "aes8192";
				else if (pos==6) aes = "aes16384";
				else if (pos==7) aes = "aes32768";

				std::string pathdb;
				if ((cfg_parse_result) && (cfg.cmdparam.wbaes_my_private_path.size()>0))
				{
					pathdb = cfg.cmdparam.wbaes_my_private_path;
					std::cout << "Folder where key tables (*.tbl) will be saved [using wbaes_my_private_path in config]: " << pathdb << std::endl;
				}
				else
				{
					std::cout << "Enter path where to save key tables (*.tbl) " << " (0 = current directory) : ";
					std::cin >> pathdb;
					if (pathdb == "0") pathdb = "./";
				}
			
				std::string pathkey;
				if ((cfg_parse_result) && (cfg.cmdparam.folder_local.size()>0))
				{
					pathkey = cfg.cmdparam.folder_local;
					std::cout << "Folder where key input file will be read [using local folder in config]: " << pathkey << std::endl;
				}
				else
				{
					std::cout << "Enter path where to find key input files " << " (0 = current directory) : ";
					std::cin >> pathkey;
					if (pathkey == "0") pathkey = "./";
				}
				
				std::cout << "Enter key name (5 *.tbl files are generated): ";
				std::string kn;
				std::cin >> kn;
				if (kn.size()==0)
				{
                    std::cout << "ERROR keyname empty" << std::endl;
                    return -1;
				}

				kn = kn + std::string("_") + cryptoAL::parsing::get_current_time_and_date_short();
				std::cout << "key name is: " << kn << std::endl;

				std::string file_for_key;
				std::string file_for_xor;

				std::cout << "Enter file to use to generate the key (0 = binary.dat.1) : ";
				std::cin >> file_for_key;
				if (file_for_key.size()==0)
                {
                    std::cout << "ERROR empty filename " << std::endl;
                    return -1;
				}
				if (file_for_key == "0") file_for_key = "binary.dat.1";
				file_for_key = pathkey + file_for_key;
				std::cout << "file to use to generate the key is: " << file_for_key << std::endl;

				std::cout << "Enter file to use to generate the xor (0 = binary.dat.2) : ";
				std::cin >> file_for_xor;
				if (file_for_xor.size()==0)
				{
                    std::cout << "ERROR empty filename " << std::endl;
                    return -1;
				}
				if (file_for_xor == "0") file_for_xor = "binary.dat.2";
				file_for_xor = pathkey + file_for_xor;
				std::cout << "file to use to generate the xor is: " << file_for_xor << std::endl;

				std::string pos_for_key;
				std::string pos_for_xor;
				long long pos1;
				long long pos2;

				std::cout << "Enter file position for key (0 = first byte) : ";
				std::cin >> pos_for_key;
				if (pos_for_key.size()==0)
                {
                    std::cout << "ERROR empty position " << std::endl;
                    return -1;
				}
				if (pos_for_key == "0") pos1 = 0;
				pos1 = cryptoAL::parsing::str_to_ll(pos_for_key);
				if (pos1 < 0) pos1 = 0;
				std::cout << "file position for key is: " << pos1 << std::endl;

				std::cout << "Enter file position for xor (0 = first byte) : ";
				std::cin >> pos_for_xor;
				if (pos_for_xor.size()==0)
				{
                    std::cout << "ERROR empty position " << std::endl;
                    return -1;
				}
				if (pos_for_xor == "0") pos2 = 0;
				pos2 = cryptoAL::parsing::str_to_ll(pos_for_xor);
				if (pos2 < 0) pos2 = 0;
				std::cout << "file position for xor is: " << pos2 << std::endl;

				int r = WBAES::generate_aes(file_for_key, (uint32_t)pos1, file_for_xor, (uint32_t)pos2, aes, pathdb, kn, true);		// CREATE
				if (r!=0)
				{
					std::cerr << "ERROR creating aes" << std::endl;
					return -1;
				}
				
				WBAES::wbaes_instance_mgr aes_instance_mgr(aes, pathdb, kn, true, true);	// LOAD
				WBAES::wbaes_vbase* paes = aes_instance_mgr.get_aes();
				if (paes == nullptr)
				{
                    std::cerr << "ERROR unable to load aes" << std::endl;
					return -1;
				}
				int N = 2 * paes->key_length(); // 2x test

				std::string splain 		= cryptoAL::random::generate_base16_random_string(2*N); // 2 * for base16
				std::string splaincopy 	= splain;
				size_t plainLen = splain.size();

				std::vector<uint8_t> eout(plainLen, 0);
				std::vector<uint8_t> dout(plainLen, 0);

				//NO KEY!!!!!!!!!!!!!!!!!! but BIG *.tbl
				const unsigned char iv[16] = {0x60, 0x61, 0x82, 0x93, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

				// aes
				std::cout << "AES test message: ";
				for(size_t i=0;i<plainLen;i++) std::cout << (int)splain[i];
				std::cout <<std::endl;

				paes->aes_whitebox_encrypt_cfb(iv, (uint8_t*)splaincopy.data(), plainLen, eout.data());
				std::cout << "AES encrypt: ";
				for(size_t i=0;i<plainLen;i++) std::cout << (int)eout[i];
				std::cout <<std::endl;

				paes->aes_whitebox_decrypt_cfb(iv, eout.data(), plainLen, dout.data());
				std::cout << "AES decrypt: ";
				for(size_t i=0;i<plainLen;i++) std::cout << (int)dout[i];
				std::cout <<std::endl;

				for(size_t i=0;i<plainLen;i++)
				{
					if (dout[i] != splain[i])
					{
						std::cout << "Error with binary AES cfb algo "<< i <<std::endl;
						std::cout << (int)dout[i]<<std::endl;
						std::cout << (int)splain[i]<<std::endl;
						break;
					}
				}
				std::cout << "TEST OK with AES cfb algo "<<std::endl;

			}
        }
        return r;
    }

/* HEX
        else if (choice == 3)
        {
            std::cout << "HEX(file, position, keysize)" << std::endl;
            std::cout << "Enter filename: ";
            std::string sfile;
            std::cin >> sfile;

            std::cout << "Enter position: ";
            std::string spos;
            std::cin >> spos;
            long long pos = cryptoAL::parsing::str_to_ll(spos);

            std::cout << "Enter keysize: ";
            std::string skeysize;
            std::cin >> skeysize;
            long long keysize = cryptoAL::parsing::str_to_ll(skeysize);

            qaclass qa;
            auto r = file_util::HEX(sfile, pos, keysize);
            std::cout << "HEX(" << sfile << "," << pos << "," << keysize << ") = " << r << std::endl;
            std::cout << std::endl;
        }
*/
}
