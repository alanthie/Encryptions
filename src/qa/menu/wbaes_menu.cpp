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
//[1] Create one or multiple WB AES key
//[2] Create one or multiple WB AES key from instruction file

	std::vector<std::string> get_directory_files(const std::string& folder, const std::string& prefix = "binary.dat.", bool check_ending_as_number = true)
	{
		std::vector<std::string> vbin;
	 	std::vector<std::string> v = file_util::files_in_directory(folder);
		for(size_t i=0;i<v.size();i++)
		{
            // TODO last "/" or "\" marker
			size_t pbin = v[i].rfind(prefix);
			if (pbin!=std::string::npos)
			{
				std::string short_name = v[i].substr(pbin);

				if (check_ending_as_number)
				{
					size_t p = short_name.find_last_of(".");
					if (p!=std::string::npos)
					{
						std::string snum = short_name.substr(p+1);
						long long l = cryptoAL::strutil::str_to_ll(snum);
						if (l>=0)
						{
							vbin.push_back(short_name);
						}
					}
				}
				else
				{
                    size_t pslash = v[i].rfind("/");
					if (pslash!=std::string::npos)
					{
						std::string s = v[i].substr(pslash+1);
						size_t t = s.find(prefix);
						if (t!=std::string::npos)
						{
							vbin.push_back(v[i].substr(pslash+1));
							//std::cout  << v[i].substr(pslash+1)<<  std::endl;
						}
					}
					else
					{
						pslash = v[i].rfind("\\");
						if (pslash!=std::string::npos)
						{
							std::string s = v[i].substr(pslash+1);
							size_t t = s.find(prefix);
							if (t!=std::string::npos)
							{
								vbin.push_back(v[i].substr(pslash+1));
								//std::cout  << v[i].substr(pslash+1)<<  std::endl;
							}
						}
					}
				}
			}
		}
		return vbin;
	}

	bool read_build_info(const std::string& buidinfo_file, std::map<std::string, std::string>& map_kv)
	{
        bool r = true;
        if (file_util::fileexists(buidinfo_file))
        {
            cryptoAL::cryptodata file_data;
            bool rr = file_data.read_from_file(buidinfo_file);
            if (rr)
            {
                std::vector<std::string> vlines;
                cryptoAL::parsing::parse_lines(file_data, vlines, 1, 1000);

                std::vector<std::string> vtoken;
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
            }
            else
            {
                std::cerr << "ERROR reading file " << buidinfo_file <<  std::endl;
                r = false;
            }
        }
        else
        {
            std::cerr << "ERROR no file " << buidinfo_file <<  std::endl;
            r = false;
        }
        return r;
    }


	int main_menu::fWBAES(size_t choice)
   	{
        int r = 0;

        if (choice == 1)
        {
			if (true)
			{
				long long REPEAT = 1;

			    std::cout << "Select the WBAES type: 1=AES512, 2=AES1024, 3=AES2048, 4=AES4096, 5=AES8192, 6=AES16384, 7=AES32768 ";
				std::string spos;
				spos = get_input_string();
				long long pos = cryptoAL::parsing::str_to_ll(spos);
				if (pos<1) pos = 1;
				if (pos>7) pos = 7;

				std::string aes;
				if      (pos==1) aes = cryptoAL::algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512);
				else if (pos==2) aes = cryptoAL::algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024);
				else if (pos==3) aes = cryptoAL::algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048);
				else if (pos==4) aes = cryptoAL::algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096);
				else if (pos==5) aes = cryptoAL::algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192);
				else if (pos==6) aes = cryptoAL::algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384);
				else if (pos==7) aes = cryptoAL::algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768);

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
					std::cout << "Enter path where to find key/xor input files " << " (0 = current directory) : ";
					pathkey = get_input_string();
					if (pathkey == "0") pathkey = "./";
				}

				std::cout << "Enter key name prefix (5 *.tbl files are generated): ";
				std::string kn;
				kn = get_input_string();
				if (kn.size()==0)
				{
                    std::cout << "ERROR keyname empty" << std::endl;
                    return -1;
				}

				std::cout << "Enter number of WBAES keys to generate (each WBAES key create 5 *.tbl): ";
				std::string srepeat;
				srepeat = get_input_string();
				REPEAT = cryptoAL::strutil::str_to_ll(srepeat);
				if (REPEAT <= 0) REPEAT = 1;
				std::string keyname_iter;

				std::vector<std::string> vbin = get_directory_files(pathkey, "binary.dat.");

				for(long long repeat = 0; repeat < REPEAT; repeat++)
				{
					std::cout << "---------------------------" << std::endl;
					std::cout << "iteration : " << repeat+1    << std::endl;
					std::cout << "---------------------------" << std::endl;

					keyname_iter = kn + std::string("_") + std::to_string(repeat+1) + std::string("_") +cryptoAL::parsing::get_current_time_and_date_short();
					std::cout << "key name is: " << keyname_iter << std::endl;

					std::string file_for_key;
					std::string file_for_xor;
					std::string short_file_for_key;
					std::string short_file_for_xor;
					long long pos1;
					long long pos2;

					if (vbin.size() > 0)
					{
						uint32_t n;
						std::cout << "key/xor will be extracted randomly from binary.dat.* files" << std::endl;

						n = cryptoAL::random::get_random_number_modulo_max((uint32_t)vbin.size());
						short_file_for_key = vbin[n];

						n = cryptoAL::random::get_random_number_modulo_max((uint32_t)vbin.size());
						short_file_for_xor = vbin[n];

						file_for_key = pathkey + short_file_for_key;
						file_for_xor = pathkey + short_file_for_xor;

						pos1 = cryptoAL::random::get_random_number_modulo_max((uint32_t)file_util::filesize(file_for_key) / 2 );
						pos2 = cryptoAL::random::get_random_number_modulo_max((uint32_t)file_util::filesize(file_for_xor) / 2 );
					}
					else
					{
						std::cout << "Enter key input file to use to generate the key tables (0 = binary.dat.1) : ";
						file_for_key = get_input_string();
						if (file_for_key.size()==0)
						{
							std::cout << "ERROR empty filename " << std::endl;
							return -1;
						}
						if (file_for_key == "0") file_for_key = "binary.dat.1";
						short_file_for_key = file_for_key;
						file_for_key = pathkey + file_for_key;
						if (file_util::fileexists(file_for_key) == false)
						{
							std::cout << "ERROR no file: " << file_for_key << std::endl;
							return -1;
						}
						std::cout << "key input file to use to generate the key is: " << file_for_key << std::endl;

						std::cout << "Enter xor input file to use to generate the xor table (0 = binary.dat.2) : ";
						file_for_xor = get_input_string();
						if (file_for_xor.size()==0)
						{
							std::cout << "ERROR empty filename " << std::endl;
							return -1;
						}
						if (file_for_xor == "0") file_for_xor = "binary.dat.2";
						short_file_for_xor = file_for_xor;
						file_for_xor = pathkey + file_for_xor;
						if (file_util::fileexists(file_for_xor) == false)
						{
							std::cout << "ERROR no file: " << file_for_xor << std::endl;
							return -1;
						}
						std::cout << "file to use to generate the xor is: " << file_for_xor << std::endl;

						pos1 = cryptoAL::random::get_random_number_modulo_max(file_util::filesize(file_for_key) / 2 );
						pos2 = cryptoAL::random::get_random_number_modulo_max(file_util::filesize(file_for_xor) / 2 );
					}

					// GENERATE key tables
					int r = WBAES::generate_aes(short_file_for_key,
												short_file_for_xor,
												file_for_key, (uint32_t)pos1,
												file_for_xor, (uint32_t)pos2,
												aes, pathdb, keyname_iter, true, true);		// CREATE
					if (r!=0)
					{
						std::cerr << "ERROR creating aes" << std::endl;
						return -1;
					}

					// LOAD and TEST key from tables
					WBAES::wbaes_instance_mgr aes_instance_mgr(aes, pathdb, keyname_iter, true, true);
					WBAES::wbaes_vbase* paes = aes_instance_mgr.get_aes();
					if (paes == nullptr)
					{
						std::cerr << "ERROR unable to load wbaes" << std::endl;
						return -1;
					}
					WBAES::validate_wbaes_key(paes, true);

					std::cout << std::endl;
				} // repeat
			}
        }

		else if (choice == 2)
        {
			std::cout << "Select 1 (to create a single WBAES) or (2 to create multiple WBAES) from instuction file(s) (*build_info.tbl): ";
			long long COUNT = 1;
            std::string howmany = get_input_string();
			COUNT = cryptoAL::strutil::str_to_ll(howmany);
            if (COUNT<=1) COUNT = 1;

            std::string buidinfo_file;      // (COUNT==1)
			std::string buidinfo_directory; // (COUNT>1)
			if (COUNT==1)
			{
				std::cout << "Enter the instruction file to use to generate wbaes key tables: ";
				std::string buidinfo_file = get_input_string();
				if (buidinfo_file.size()==0)
				{
					std::cout << "ERROR empty filename " << std::endl;
					return -1;
				}
			}
			else
			{
				if ((cfg_parse_result) && (cfg.cmdparam.wbaes_my_private_path.size()>0))
				{
					buidinfo_directory = cfg.cmdparam.wbaes_my_private_path;
					std::cout << "Folder where instuction files (*build_info.tbl) will be read [using wbaes_my_private_path in config]: " << cfg.cmdparam.wbaes_my_private_path << std::endl;
				}
				else
				{
					std::cout << "Enter path where instuction files (*build_info.tbl) will be read " << " (0 = current directory) : ";
					buidinfo_directory = get_input_string();
					if (buidinfo_directory == "0") buidinfo_directory = "./";
				}
			}

			std::vector<std::string> vbuild_info;
			if (COUNT>1)
			{
				vbuild_info = get_directory_files(buidinfo_directory, "_build_info.tbl", false);
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

			long long REPEAT = 1;
			if (COUNT>1)
			{
				REPEAT = vbuild_info.size();
			}

			for(long long repeat = 0; repeat < REPEAT; repeat++)
			{
                std::cout << "---------------------------" << std::endl;
                std::cout << "iteration : " << repeat+1    << std::endl;
                std::cout << "---------------------------" << std::endl;

				if (COUNT>1)
				{
					buidinfo_file = buidinfo_directory + vbuild_info[repeat];
				}
				std::cout << "reading buid info file: " << buidinfo_file  << std::endl;

				std::map<std::string, std::string> map_kv;
				bool rr = read_build_info(buidinfo_file, map_kv);
				if (rr)
				{
					// Check...
					{
						if  ((cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filekey")]) >= 0) &&
							 (cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filexor")]) >= 0))
						{
							if ( (file_util::fileexists(pathkey + map_kv[std::string("filekey")]))  &&
								 (file_util::fileexists(pathkey + map_kv[std::string("filexor")]))  )
							{
								if ( (file_util::file_checksum(pathkey + map_kv[std::string("filekey")]) == map_kv[std::string("sha_filekey")]) &&
									 (file_util::file_checksum(pathkey + map_kv[std::string("filexor")]) == map_kv[std::string("sha_filexor")]) )
								{
									int rc = WBAES::generate_aes(
															map_kv[std::string("filekey")], 		    //short_file_for_key,
															map_kv[std::string("filexor")], 			//short_file_for_xor,
															pathkey + map_kv[std::string("filekey")], 	//file_for_key,
															(uint32_t)cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filekey")]), //(uint32_t)pos1,
															pathkey + map_kv[std::string("filexor")], 	//file_for_xor,
															(uint32_t)cryptoAL::strutil::str_to_ll(map_kv[std::string("pos_filexor")]), //(uint32_t)pos2,
															map_kv[std::string("aes")], 				//aes,
															pathdb,
															map_kv[std::string("key")], 				//key,
															true,
															true);		// CREATE
									if (rc!=0)
									{
										std::cerr << "ERROR creating aes" << std::endl;
										return -1;
									}

									// LOAD and TEST key from tables
									WBAES::wbaes_instance_mgr aes_instance_mgr(map_kv[std::string("aes")], pathdb, map_kv[std::string("key")], true, true);
									WBAES::wbaes_vbase* paes = aes_instance_mgr.get_aes();
									if (paes == nullptr)
									{
										std::cerr << "ERROR unable to load wbaes" << std::endl;
										return -1;
									}
									WBAES::validate_wbaes_key(paes, true);
								}
								else
								{
									std::cerr << "ERROR - SHA256 of file mismatch in build instruction" << std::endl;
									std::cerr << "File: " << pathkey + map_kv[std::string("filekey")] << std::endl;
									std::cerr <<  "SHA256: " << file_util::file_checksum(pathkey + map_kv[std::string("filekey")])
											  <<  " vs " << map_kv[std::string("sha_filekey")]
											  << std::endl;
									std::cerr << "File: " << pathkey + map_kv[std::string("filexor")] << std::endl;
									std::cerr <<  "SHA256: " << file_util::file_checksum(pathkey + map_kv[std::string("filexor")])
											  <<  " vs " << map_kv[std::string("sha_filexor")]
											  << std::endl;
									return -1;
								}
							}
							else
							{
								if (file_util::fileexists(pathkey + map_kv[std::string("filekey")]) == false)
									std::cerr << "ERROR no file " << pathkey + map_kv[std::string("filekey")] << std::endl;
								if (file_util::fileexists(pathkey + map_kv[std::string("filexor")]) == false)
									std::cerr << "ERROR no file " << pathkey + map_kv[std::string("filexor")] << std::endl;
								return -1;
							}
						}
						else
						{
							std::cerr << "ERROR invalid position" << std::endl;
							return -1;
						}
					}
				}
				else
				{
					std::cerr << "ERROR reading build info file: " << buidinfo_file <<  std::endl;
					return -1;
				}
			}
			std::cout << std::endl;
		}

        return r;
    }

}
