#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../../../src/crypto_strutil.hpp"
#include "../aes-whitebox/aes_whitebox.hpp"
#include "../aes-whitebox/aes_whitebox_compiler.hpp"
#include "../../../src/c_plus_plus_serializer.h"
#include "menu.h"

namespace ns_menu
{
//[1] Create a WB AES key
//[2] Create multiple WB AES keys
//[3] Create a WB AES key from instruction file
//[4] Create multiple WB AES key from multiple instruction files

	int main_menu::fWBAES(int choice)
   	{
        int r = 0;
        if (choice == 1)
        {
			if (true)
			{
			    std::cout << "Select one 1=AES512, 2=AES1024, 3=AES2048, 4=AES4096, 5=AES8192, 6=AES16384, 7=AES32768 ";
				std::string spos;
				spos = get_input_string();
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
					pathdb = get_input_string();
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
					pathkey = get_input_string();
					if (pathkey == "0") pathkey = "./";
				}

				std::cout << "Enter key name (5 *.tbl files are generated): ";
				std::string kn;
				kn = get_input_string();
				if (kn.size()==0)
				{
                    std::cout << "ERROR keyname empty" << std::endl;
                    return -1;
				}

				kn = kn + std::string("_") + cryptoAL::parsing::get_current_time_and_date_short();
				std::cout << "key name is: " << kn << std::endl;

				std::string file_for_key;
				std::string file_for_xor;
				std::string short_file_for_key;
				std::string short_file_for_xor;

				std::cout << "Enter file to use to generate the key (0 = binary.dat.1) : ";
				file_for_key = get_input_string();
				if (file_for_key.size()==0)
                {
                    std::cout << "ERROR empty filename " << std::endl;
                    return -1;
				}
				if (file_for_key == "0") file_for_key = "binary.dat.1";
				short_file_for_key = file_for_key;
				file_for_key = pathkey + file_for_key;
				std::cout << "file to use to generate the key is: " << file_for_key << std::endl;

				std::cout << "Enter file to use to generate the xor (0 = binary.dat.2) : ";
				file_for_xor = get_input_string();
				if (file_for_xor.size()==0)
				{
                    std::cout << "ERROR empty filename " << std::endl;
                    return -1;
				}
				if (file_for_xor == "0") file_for_xor = "binary.dat.2";
				short_file_for_xor = file_for_xor;
				file_for_xor = pathkey + file_for_xor;
				std::cout << "file to use to generate the xor is: " << file_for_xor << std::endl;

				std::string pos_for_key;
				std::string pos_for_xor;
				long long pos1;
				long long pos2;

				std::cout << "Enter file position for key (0 = first byte) : ";
				pos_for_key = get_input_string();
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
				pos_for_xor = get_input_string();
				if (pos_for_xor.size()==0)
				{
                    std::cout << "ERROR empty position " << std::endl;
                    return -1;
				}
				if (pos_for_xor == "0") pos2 = 0;
				pos2 = cryptoAL::parsing::str_to_ll(pos_for_xor);
				if (pos2 < 0) pos2 = 0;
				std::cout << "file position for xor is: " << pos2 << std::endl;

				int r = WBAES::generate_aes(short_file_for_key,
											short_file_for_xor,
											file_for_key, (uint32_t)pos1,
											file_for_xor, (uint32_t)pos2,
											aes, pathdb, kn, true, true);		// CREATE
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
				std::cout << "KEY OK for WB AES "<<std::endl;

			}
        }

		else if (choice == 3)
        {
			cryptoAL::cryptodata file_data;
			std::vector<std::string> vlines;

			// TODO...
            std::cout << "Enter instruction file to use to generate tables: ";
            std::string buidinfo_file = get_input_string();
            if (buidinfo_file.size()==0)
            {
                std::cout << "ERROR empty filename " << std::endl;
                return -1;
            }

			std::string pathdb;
			if ((cfg_parse_result) && (cfg.cmdparam.wbaes_my_private_path.size()>0))
			{
				pathdb = cfg.cmdparam.wbaes_my_private_path;
				std::cout << "Folder where key tables (*.tbl) will be saved [using wbaes_my_private_path in config]: " << pathdb << std::endl;
			}
			else
			{
				std::cout << "Enter path where to save key tables (*.tbl) " << " (0 = current directory) : ";
				pathdb = get_input_string();
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
				pathkey = get_input_string();
				if (pathkey == "0") pathkey = "./";
			}

			if (file_util::fileexists(buidinfo_file))
			{
				bool rr = file_data.read_from_file(buidinfo_file);
				if (rr)
				{
					cryptoAL::parsing::parse_lines(file_data, vlines, 1, 1000);

					std::vector<std::string> vtoken;
					std::map<std::string, std::string> map_kv;
                    /*
                    aes: aes1024
                    key: b_20230405212833
                    filekey: binary.dat.1
                    pos_filekey: 0
                    filexor: binary.dat.2
                    pos_filexor: 0
                    sha_filekey: edeaa387b184fc2140bda2fcbf67b33629a2c8bfeee3b7051e8c7dada7658ace
                    sha_filexor: 442e52b8ec5d9ee1a35b302415c38f7e97d130c733357022398b8165e08c6c0a
                    */
					for(size_t i = 0; i< vlines.size(); i++)
					{
						vtoken = cryptoAL::parsing::split(vlines[i], ":");
						if (vtoken.size() >= 2)
						{
							cryptoAL::strutil::trim(vtoken[0]);
							cryptoAL::strutil::trim(vtoken[1]);
							if      (vtoken[0] == std::string("aes") )			{map_kv[vtoken[0]] = vtoken[1];}
							else if (vtoken[0] == std::string("key")  )			{map_kv[vtoken[0]] = vtoken[1];}
							else if (vtoken[0] == std::string("filekey")  )		{map_kv[vtoken[0]] = vtoken[1];}
							else if (vtoken[0] == std::string("pos_filekey") ) 	{map_kv[vtoken[0]] = vtoken[1];}
							else if (vtoken[0] == std::string("filexor")  )		{map_kv[vtoken[0]] = vtoken[1];}
							else if (vtoken[0] == std::string("pos_filexor") ) 	{map_kv[vtoken[0]] = vtoken[1];}
							else if (vtoken[0] == std::string("sha_filekey") ) 	{map_kv[vtoken[0]] = vtoken[1];}
							else if (vtoken[0] == std::string("sha_filexor") ) 	{map_kv[vtoken[0]] = vtoken[1];}
						}
					}

					if  ((cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filekey")]) >= 0) &&
                         (cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filexor")]) >= 0))
                    {
                        if ( (file_util::fileexists(pathkey + map_kv[std::string("filekey")]))  &&
                             (file_util::fileexists(pathkey + map_kv[std::string("filexor")]))  )
                        {
                            int rc = WBAES::generate_aes(
                                                    map_kv[std::string("filekey")], 		    //short_file_for_key,
													map_kv[std::string("filexor")], 			//short_file_for_xor,
													pathkey + map_kv[std::string("filekey")], 	//file_for_key,
													(uint32_t)cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filekey")]), //(uint32_t)pos1,
													pathkey + map_kv[std::string("filexor")], 	//file_for_xor,
													(uint32_t)cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filexor")]), //(uint32_t)pos2,
													map_kv[std::string("aes")], //aes,
													pathdb,
													map_kv[std::string("key")], //kn,
													true,
													true);		// CREATE
                            if (rc!=0)
                            {
                                std::cerr << "ERROR creating aes" << std::endl;
                                return -1;
                            }
                        }
                        else
                        {
                            std::cerr << "ERROR no file " << pathkey + map_kv[std::string("filekey")] << std::endl;
                            std::cerr << "ERROR no file " << pathkey + map_kv[std::string("filexor")] << std::endl;
                            return -1;
                        }
                    }
                    else
                    {
                        std::cerr << "ERROR invalid position" << std::endl;
                        return -1;
                    }

					// TODO...

				}
				else
				{
					std::cerr << "ERROR reading file " << buidinfo_file <<  std::endl;
					return -1;
				}
			}
			else
			{
				std::cerr << "ERROR no file " << buidinfo_file <<  std::endl;
				return -1;
			}
		}

        return r;
    }

}
