#ifndef _INCLUDES_encryptor
#define _INCLUDES_encryptor

#include "crypto_const.hpp"
#include <iostream>
#include <fstream>
#include "DES.h"
#include "AESa.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_urlkey.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "twofish.h"
#include "Salsa20.h"
#include "IDEA.hpp"
#include "crc32a.hpp"
#include "crypto_shuffle.hpp"
#include "crypto_history.hpp"
#include "cryptodata_list.hpp"
#include "crypto_keymgr.hpp"
#include "crypto_key_parser.hpp"
#include "crypto_cfg.hpp"
#include "crypto_png.hpp"

namespace cryptoAL
{

static bool s_Twofish_initialise = false;

class encryptor
{
// main use is: bool encrypt()

friend class crypto_package;
private:
    encryptor() : cfg("") {}

public:

    encryptor(  std::string ifilename_cfg,
                std::string ifilename_urls,             // INPUT  (optional) FILE - URL for making KEYS
                std::string ifilename_msg_data,         // INPUT  (required) FILE - PLAINTEXT DATA to encrypt
                std::string ifilename_puzzle,           // INPUT  (optional) FILE - fully resolved puzzle - first key
                std::string ifilename_partial_puzzle,   // OUTPUT (optional) FILE - unresolved formatted qa puzzle with checksum
                std::string ifilename_full_puzzle,      // OUTPUT (optional) FILE - fullt resolved formatted puzzle with checksum
                std::string ifilename_encrypted_data,   // OUTPUT (required) FILE - ENCRYPTED DATA
                std::string istaging,                   // Environment - staging path
                std::string ifolder_local,              // Environment - local data keys file path
                std::string ifolder_my_private_rsa,     // Environment - RSA database *.db path
				std::string ifolder_other_public_rsa,   // Environment
				std::string ifolder_my_private_ecc,
                std::string ifolder_other_public_ecc,
                std::string ifolder_my_private_hh,
                std::string ifolder_other_public_hh,
                bool verb = false,                      // Flag - verbose
                bool keep = false,                      // Flag - keep staging files
                std::string iencryped_ftp_user = "",
                std::string iencryped_ftp_pwd  = "",
                std::string iknown_ftp_server  = "",
                long ikey_size_factor = 1,              // Parameter - keys size multiplier
				bool iuse_gmp = false,                  // Flag - use gmp for big computation
				bool iself_test = false,                // Flag - verify encryption
				long ishufflePerc = 0,                  // Parameter - shuffling percentage
				bool autoflag = false,
				uint32_t iconverter = 0)
        : cfg (ifilename_cfg, false)
    {
        filename_cfg = ifilename_cfg;
        filename_urls = ifilename_urls;
        filename_msg_data = ifilename_msg_data;
        filename_puzzle = ifilename_puzzle;
        filename_partial_puzzle = ifilename_partial_puzzle;
        filename_full_puzzle = ifilename_full_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;

        staging = istaging;
        folder_local = ifolder_local;
        folder_my_private_rsa   = ifolder_my_private_rsa;
		folder_other_public_rsa = ifolder_other_public_rsa;
		folder_my_private_ecc   = ifolder_my_private_ecc;
		folder_other_public_ecc = ifolder_other_public_ecc;
        folder_my_private_hh    = ifolder_my_private_hh;
        folder_other_public_hh  = ifolder_other_public_hh;

        verbose = verb;
        keeping = keep;
        encryped_ftp_user = iencryped_ftp_user;
        encryped_ftp_pwd  = iencryped_ftp_pwd;
        known_ftp_server  = iknown_ftp_server;

        key_size_factor = ikey_size_factor;

		use_gmp 	= iuse_gmp;
		self_test 	= iself_test;
		shufflePerc = ishufflePerc;
		auto_flag 	= autoflag;
		converter 	= iconverter;

        puz.verbose = verb;

        if (filename_cfg.size() > 0)
        {
            cfg_parse_result = cfg.parse();
            if (cfg_parse_result)
            {
                process_cfg_param();
            }
        }

		if (key_size_factor < 1) key_size_factor = 1;

        if (staging.size()==0)
        {
            staging ="./";
        }

		if (shufflePerc > 100) shufflePerc = 100;

        if (filename_partial_puzzle.size() == 0)
        {
            if (filename_full_puzzle.size() > 0)
                filename_partial_puzzle = filename_full_puzzle + ".qa";
        }

        if (filename_encrypted_data.size() == 0)
        {
            if (filename_msg_data.size() > 0)
                filename_encrypted_data = filename_msg_data + ".encrypted";
        }

        if (verbose)
            show_param();
    }

    ~encryptor()
    {
    }

	void process_cfg_param()
	{
		if (filename_urls.size() == 0) 			filename_urls 		= cfg.cmdparam.filename_urls;
		if (filename_msg_data.size() == 0) 		filename_msg_data 	= cfg.cmdparam.filename_msg_data;
		if (filename_puzzle.size() == 0) 		filename_puzzle 	= cfg.cmdparam.filename_puzzle;
		if (filename_full_puzzle.size() == 0) 	filename_full_puzzle = cfg.cmdparam.filename_full_puzzle;
		if (filename_encrypted_data.size() == 0) filename_encrypted_data = cfg.cmdparam.filename_encrypted_data;

		if (staging.size() == 0) 				staging 				= cfg.cmdparam.folder_staging;
		if (folder_local.size() == 0) 			folder_local 			= cfg.cmdparam.folder_local;
		if (folder_my_private_rsa.size() == 0) 	folder_my_private_rsa 	= cfg.cmdparam.folder_my_private_rsa;
		if (folder_other_public_rsa.size() == 0)folder_other_public_rsa = cfg.cmdparam.folder_other_public_rsa;
		if (folder_my_private_ecc.size() == 0) 	folder_my_private_ecc 	= cfg.cmdparam.folder_my_private_ecc;
		if (folder_other_public_ecc.size() == 0)folder_other_public_ecc = cfg.cmdparam.folder_other_public_ecc;
		if (folder_my_private_hh.size() == 0)	folder_my_private_hh 	= cfg.cmdparam.folder_my_private_hh;
		if (folder_other_public_hh.size() == 0)	folder_other_public_hh 	= cfg.cmdparam.folder_other_public_hh;

		if (verbose == false) 					if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.verbose) == 1) verbose = true;
		if (keeping == false) 					if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.keeping) == 1) keeping = true;
		if (use_gmp == false) 					if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.use_gmp) == 1) use_gmp = true;
		if (self_test == false) 				if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.self_test) == 1) self_test = true;
		if (auto_flag == false) 				if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.auto_flag) == 1) auto_flag = true;

		if (shufflePerc == 0) 					{if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.shufflePerc) > 0) shufflePerc = cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.shufflePerc);}
		if (key_size_factor <= 1) 				{if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.key_size_factor) >= 1) key_size_factor = cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.key_size_factor);}
		if (converter <= 1) 					{if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.converter) >= 1) converter = cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.converter);}
	}

	void show_param()
	{
		std::cout << "-------------------------------------------------" << std::endl;
		std::cout << "parameters:" << std::endl;
		std::cout << "-------------------------------------------------" << std::endl;
        std::cout << "filename_urls:           " << filename_urls << std::endl;
        std::cout << "filename_msg_data:       " << filename_msg_data << std::endl;
        std::cout << "filename_puzzle:         " << filename_puzzle << std::endl;
        std::cout << "filename_full_puzzle:    " << filename_full_puzzle << std::endl;
        std::cout << "filename_encrypted_data: " << filename_encrypted_data << std::endl;

        std::cout << "staging folder:          " << staging << std::endl;
        std::cout << "folder_local:            " << folder_local << std::endl;
        std::cout << "folder_my_private_rsa:   " << folder_my_private_rsa << std::endl;
        std::cout << "folder_other_public_rsa: " << folder_other_public_rsa << std::endl;
        std::cout << "folder_my_private_ecc:   " << folder_my_private_ecc << std::endl;
        std::cout << "folder_other_public_ecc: " << folder_other_public_ecc << std::endl;
        std::cout << "folder_my_private_hh:    " << folder_my_private_hh << std::endl;
        std::cout << "folder_other_public_hh:  " << folder_other_public_hh << std::endl;

        std::cout << "keeping:     " << keeping << std::endl;
        std::cout << "use_gmp:     " << use_gmp << std::endl;
        std::cout << "self_test:   " << self_test << std::endl;
        std::cout << "auto_flag:   " << auto_flag << std::endl;
        std::cout << "shufflePerc: " << shufflePerc << std::endl;
        std::cout << "key_size_factor: " << key_size_factor << std::endl;
		std::cout << "converter:   " << converter << std::endl;
		std::cout << "verbose:     " << verbose << std::endl;
		std::cout << "-------------------------------------------------" << std::endl<< std::endl;
	}

    bool read_file_urls(std::string filename)
    {
        bool r = true;
        r = urls_data.read_from_file(filename);

        if (r)
        {
			if (USE_KEYURL_FEATURE)
			{
				keyspec_parser kp;
				kp.parse(urls_data);

				for(size_t i=0;i<kp.vkeyspec_composite.size();i++)
				{
					for(size_t j=0;j<kp.vkeyspec_composite[i].vkeyspec.size();j++)
					{
						if (kp.vkeyspec_composite[i].vkeyspec[j].is_spec)
						{
							bool t = keymgr::materialize_keys(	kp.vkeyspec_composite[i].vkeyspec[j],
																folder_other_public_rsa,
																folder_other_public_ecc,
																folder_my_private_hh,
																folder_my_private_ecc,
																verbose);
							if (t==false)
							{
								//... warn
							}
						}
					}
				}
				if (verbose)
					kp.show();

				for(size_t i=0;i<kp.vkeyspec_composite.size();i++)
				{
					std::string s = kp.vkeyspec_composite[i].format_key_line(1, verbose);
					if (verbose) std::cout << "url[]: " << s << std::endl;

					if ((s.size() >= URL_MIN_SIZE ) && (s.size() < URL_MAX_SIZE ))
					{
						urlkey uk;
						for(uint32_t ii=0;ii<URL_MAX_SIZE;ii++) uk.url[ii] = 0;
						uint32_t idx2 = 0;
						for (uint32_t ii = 0; ii < s.size(); ii++)
						{
							if ((s[ii] != '\n') && (s[ii] != '\r'))
								uk.url[idx2] = s[ii];
							idx2++;
						}
						uk.url_size = idx2;
						vurlkey.push_back(uk);;
					}
				}
			}
			else
			{
			  	char c;
				std::string s;
				char url[URL_MAX_SIZE] = { 0 };
				int pos = -1;
				uint32_t idx=0;

				for(size_t i=0;i<urls_data.buffer.size();i++)
				{
					// parse url
					c = urls_data.buffer.getdata()[i];
					pos++;

					if ((c == '\n') || (i==urls_data.buffer.size()-1))
					{
						if (i==urls_data.buffer.size()-1)
						{
							if ((c!=0) && (c!='\r') && (c!='\n'))
							{
								url[idx] = c;
								idx++;
							}
						}

						uint32_t len = idx;

						if ( ((len >= URL_MIN_SIZE) && (len <= URL_MAX_SIZE)) && (url[0]!=';') )
						{
							urlkey uk;
							for(uint32_t ii=0;ii<URL_MAX_SIZE;ii++) uk.url[ii] = 0;

							uint32_t idx2=0;
							for (uint32_t ii = 0; ii < len; ii++)
							{
								if ((url[ii] != '\n') && (url[ii] != '\r'))
									uk.url[idx2] = url[ii];
								idx2++;
							}

							uk.url_size = idx2;
							vurlkey.push_back(uk);
						}
						else
						{
							// skip!
							if (len > 0)
							{
								if (url[0]!=';')
									std::cerr << "WARNING url skipped, " << "(url.size() >= URL_MIN_SIZE) && (url.size() <= URL_MAX_SIZE))  url=" << url <<std::endl;
							}
						}
						s.clear();
						for(uint32_t ii=0;ii<URL_MAX_SIZE;ii++) url[ii] = 0;
						pos = -1;
						idx = 0;
					}
					else
					{
						if ((c!=0) && (c!='\r') && (c!='\n'))
						{
							if (idx < URL_MAX_SIZE)
							{
								url[idx] = c;
								idx++;
							}
							else
							{
								std::string su(url);
								std::cerr << "WARNING url skipped, " << "url size >= URL_MAX_SIZE url=" << su << std::endl;
							}
						}
					}
				}
			}
        }
        return r;
    }

    bool make_urlkey_from_url(size_t i)
	{
		bool r = true;

        if(fs::is_directory(staging)==false)
        {
            std::cerr << "ERROR staging is not a folder: " << staging << std::endl;
            return false;
        }

        std::string file = staging + "encode_staging_url_file_" + std::to_string(staging_cnt) + ".dat";
        staging_cnt++;

        if (fileexists(file))
		    std::remove(file.data());

		// DOWNLOAD URL FILE
		bool is_video   = false;
		bool is_ftp     = false;
		bool is_local   = false;
		bool is_rsa     = false;
		bool is_ecc   	= false;
		bool is_histo   = false;
		bool is_web     = false;

		if (vurlkey[i].url[0]=='[')
		{
            if (vurlkey[i].url[1]=='v')
            {
                is_video = true;
            }
            else if (vurlkey[i].url[1]=='f')
            {
                is_ftp = true;
            }
            else if (vurlkey[i].url[1]=='l')
            {
                is_local = true;
            }
            else if (vurlkey[i].url[1]=='r')
            {
                is_rsa = true;
            }
			else if (vurlkey[i].url[1]=='e')
            {
                is_ecc = true;
            }
            else if (vurlkey[i].url[1]=='h')
            {
                is_histo = true;
            }
            else if (vurlkey[i].url[1]=='w')
            {
                is_web = true;
            }
		}

		int pos_url = 0;
		if      (is_video)  pos_url = 3;
		else if (is_ftp)    pos_url = 3;
		else if (is_local)  pos_url = 3;
		else if (is_rsa)    pos_url = 3;
		else if (is_ecc)    pos_url = 3;
		else if (is_histo)  pos_url = 3;
		else if (is_web)    pos_url = 3;
        int rc = 0;

        cryptodata dataout_local;
        cryptodata dataout_other;
        cryptodata rsa_key_data;
		cryptodata ecc_key_data;
        cryptodata histo_key_data;

        std::string embedded_rsa_key;
		std::string embedded_ecc_key;
        std::string histo_key;
        history_key kout;

        std::string s(&vurlkey[i].url[pos_url]);

        if (is_video)
        {
            rc = getvideo(s.data(), file.data(), "", verbose);
            if (rc!= 0)
            {
                std::cerr << "ERROR with getvideo using youtube-dl, error code: " << rc << " url: " << s <<  " file: " << file << std::endl;
                r = false;
            }
        }
        else if (is_local)
        {
            std::string local_url = folder_local + s;
            rc = getlocal(local_url.data(), dataout_local, "", verbose);
            if (rc!= 0)
            {
                std::cerr << "ERROR with get local file, error code: " << rc << " url: " << local_url <<  " file: " << file << std::endl;
                r = false;
            }
        }
        else if (is_ftp)
        {
            rc = getftp(s.data(), file.data(),
                        encryped_ftp_user,
                        encryped_ftp_pwd,
                        known_ftp_server,
                        "", verbose);
            if (rc!= 0)
            {
                std::cerr << "ERROR with getvideo using youtube-dl, error code: " << rc << " url: " << s <<  " file: " << file << std::endl;
                r = false;
            }
        }
        else if (is_histo)
        {
            std::string local_histo_db = folder_my_private_hh + HHKEY_MY_PRIVATE_ENCODE_DB;
            std::vector<std::string> v = split(s, ";");
            if (v.size() < 1)
            {
                std::cerr << "ERROR histo url bad format - missing histo key name: " << s << std::endl;
                r = false;
            }
            else
            {
                if (verbose)
				{
					if (v.size() == 1)
                   	 	std::cout << "unique histo key name in URL: " << v[0] << std::endl;
					else
						std::cout << "multiple histo key in URL: " << v[0] << " " << v[1] << " ..." << std::endl;
				}
            }
            if (r)
            {
                long long iseq = str_to_ll(v[0]);
                if (iseq < 0) r = false;
                if (r)
                {
                    uint32_t seq = (uint32_t)iseq;

					// TODO - Use only HH confirmed....
                    r = get_history_key(seq, local_histo_db, kout);
                    if (r)
                    {
                        histo_key = kout.data_sha[0]+kout.data_sha[1]+kout.data_sha[2];
                        if (verbose)
                        {
                            std::cout << "histo key: " << histo_key << " size:" << histo_key.size() << std::endl;
                            std::cout << "histo key: " << get_summary_hex(histo_key.data(), (uint32_t)histo_key.size()) << " size:" << histo_key.size() << std::endl;
                        }
                    }
                    else
                    {
                        std::cerr << "ERROR no histo key: " << seq << std::endl;
                    }
                }
                else
                {
                    std::cerr << "ERROR histo key no numerical: " << v[0] << std::endl;
                }
            }
        }
        else if (is_rsa)
        {
            std::vector<std::string> v = split(s, ";");
            std::vector<uint32_t> v_encoded_size(v.size(), 0 );

            if (v.size() < 1)
            {
                std::cerr << "ERROR rsa url bad format - missing rsa key name: " << s << std::endl;
                r = false;
            }
            else
            {
                if (verbose)
				{
					if (v.size() == 1)
                   	 	std::cout << "unique rsa key name in URL: " << v[0] << std::endl;
					else
						std::cout << "multiple rsa key in URL: " << v[0] << " " << v[1] << " ..." << std::endl;
				}
            }

            if (r)
            {
				bool SELF_TEST = self_test;
				std::string local_rsa_db ;

				if (SELF_TEST)
				{
					local_rsa_db = folder_my_private_rsa + RSA_MY_PRIVATE_DB;
				}
				else
				{
					local_rsa_db = folder_other_public_rsa + RSA_OTHER_PUBLIC_DB; // Encoding with a public key of the recipient of the message
				}

				// ITER
				for (size_t riter=0; riter < v.size(); riter++)
				{
				 	std::string rsa_key_at_iter = v[riter];

					generate_rsa::rsa_key kout;
					r = get_rsa_key(rsa_key_at_iter, local_rsa_db, kout);

                    if (r)
                    {
                        std::string rsa_key_at_iter = v[riter];
                        if (riter == 0)
                        {
							// generate random embedded_rsa_key
							uint32_t key_len_in_bytes = kout.key_size_in_bits/8;
							embedded_rsa_key = generate_base64_random_string(key_len_in_bytes - 11);
							vurlkey[i].sRSA_ECC_ENCODED_DATA = embedded_rsa_key;
							if (verbose)
							{
								std::cout << "rsa key_len_in_bytes: " << key_len_in_bytes << std::endl;
								std::cout << "rsa_data: " << get_summary_hex(embedded_rsa_key.data(), (uint32_t)embedded_rsa_key.size()) << " size:" << embedded_rsa_key.size() << std::endl;
							}
						}

						uint32_t msg_input_size_used = 0;
						uint32_t msg_size_produced = 0;
						std::string t = rsa_encode_string(vurlkey[i].sRSA_ECC_ENCODED_DATA, kout, msg_input_size_used, msg_size_produced, use_gmp, SELF_TEST);

						// t may grow
						vurlkey[i].sRSA_ECC_ENCODED_DATA = t;

						if (riter == 0)
						{
							if (v_encoded_size.size() > 0)
								v_encoded_size[0] = (uint32_t)vurlkey[i].sRSA_ECC_ENCODED_DATA.size();
							else
								v_encoded_size.push_back((uint32_t)vurlkey[i].sRSA_ECC_ENCODED_DATA.size() );
						}
						else
						{
							v_encoded_size[riter] = (uint32_t)msg_size_produced;
						}

						vurlkey[i].rsa_ecc_encoded_data_pos = 0; // set later
						vurlkey[i].rsa_ecc_encoded_data_len = (uint32_t)vurlkey[i].sRSA_ECC_ENCODED_DATA.size();
               		}
					else
					{
						std::cerr << "ERROR rsa_key not found: " << rsa_key_at_iter << "  in " << local_rsa_db << std::endl;
						break;
					}

				} // for (size_t riter=0; riter < v.size; riter++)

				if (r)
				{
					if (v.size() > 1)
					{
						std::string new_URL = "[r]";
						for (size_t riter=0; riter < v.size(); riter++)
						{
							std::string rsa_key_at_iter = v[riter];
							new_URL += rsa_key_at_iter;
							new_URL += std::string(";");
							new_URL += std::to_string(v_encoded_size[riter]);
							new_URL += std::string(";");
						}
						if (new_URL.size() > URL_MAX_SIZE)
						{
							std::cerr << "ERROR resursive rsa too long: " << new_URL << std::endl;
							r = false;
						}
						else
						{
							vurlkey[i].set_url(new_URL);
							if (verbose)
                            	std::cout << "RSA Recursive NEW URL: " << new_URL << " " << new_URL.size() << std::endl;
						}
					}
				}
			}
        }
		else if (is_ecc)
        {
            std::vector<std::string> v = split(s, ";");
            std::vector<uint32_t> v_encoded_size(v.size(), 0 );

            if (v.size() < 1)
            {
                std::cerr << "ERROR ecc url bad format - missing ecc key name: " << s << std::endl;
                r = false;
            }
            else
            {
                if (verbose)
				{
					if (v.size() == 1)
                   	 	std::cout << "unique ecc key name in URL: " << v[0] << std::endl;
					else
						std::cout << "multiple ecc key in URL: " << v[0] << " " << v[1] << " ..." << std::endl;
				}
            }

            if (r)
            {
				bool SELF_TEST = self_test;
				std::string local_ecc_other_db ;
				std::string local_ecc_my_db ;

				if (SELF_TEST)
				{
					local_ecc_other_db = folder_my_private_ecc + ECCKEY_MY_PRIVATE_DB;
					local_ecc_my_db    = folder_other_public_ecc  + ECCKEY_OTHER_PUBLIC_DB;
				}
				else
				{
					local_ecc_other_db = folder_other_public_ecc  + ECCKEY_OTHER_PUBLIC_DB; // Encoding with a public key of the recipient of the message
					local_ecc_my_db    = folder_my_private_ecc + ECCKEY_MY_PRIVATE_DB;
				}

                if (verbose)
                {
                    std::cout << "public  ecc keys db: " << local_ecc_other_db << std::endl;
                    std::cout << "private ecc keys db: " << local_ecc_my_db << std::endl;
                }

				// ITER
				for (size_t riter=0; riter < v.size(); riter++)
				{
				 	std::string ecc_key_at_iter = v[riter];

					ecc_key key_other;
					ecc_key key_mine;

					r = get_ecc_key(ecc_key_at_iter, local_ecc_other_db, key_other);
					if (r==false)
					{
                        std::cerr << "ERROR public ecc key not found: " << ecc_key_at_iter << std::endl;
					}
					else if (verbose)
                    {
                        std::cout << "public ecc key found: " << ecc_key_at_iter << std::endl;
                    }

					if (r)
					{
                        r = get_compatible_ecc_key(local_ecc_my_db, key_other, key_mine);
                        if (r==false)
                        {
                            std::cerr << "ERROR private compatible ecc key not found for public key: " << ecc_key_at_iter << std::endl;
                        }
                        else if (verbose)
                        {
                            std::cout << "private compatible ecc key found for domain: " << key_mine.dom.name() << std::endl;
                        }
                    }

                    if (r)
                    {
                        std::string ecc_key_at_iter = v[riter];
                        if (riter == 0)
                        {
							// generate random embedded_ecc_key
							uint32_t key_len_in_bytes = key_mine.dom.key_size_bits/8;
							embedded_ecc_key = generate_base64_random_string(key_len_in_bytes - 11);
							vurlkey[i].sRSA_ECC_ENCODED_DATA = embedded_ecc_key;
							if (verbose)
							{
								std::cout << "ecc key len in bytes:     " << key_len_in_bytes << std::endl;
								std::cout << "ecc embedded random data: " << embedded_ecc_key << " size:" << embedded_ecc_key.size() << std::endl;
								std::cout << "ecc embedded random key: " << get_summary_hex(embedded_ecc_key.data(), (uint32_t)embedded_ecc_key.size())
										  << " size:" << embedded_ecc_key.size() << std::endl;
							}
						}

						uint32_t msg_input_size_used = 0;
						uint32_t msg_size_produced = 0;

						std::string t = ecc_encode_string(	vurlkey[i].sRSA_ECC_ENCODED_DATA, key_mine,
                                                            key_other.s_kg_x, key_other.s_kg_y,
															msg_input_size_used,
															msg_size_produced, SELF_TEST, verbose);

						// t may grow
						vurlkey[i].sRSA_ECC_ENCODED_DATA = t;

						if (verbose)
						{
							std::cout << "ecc encoded data :" << t << " size:" << t.size() << std::endl;
                            std::cout << "ecc encoded data :" << get_summary_hex(t.data(), (uint32_t)t.size()) << " size:" << t.size() << std::endl;
						}

						if (riter == 0)
						{
							if (v_encoded_size.size() > 0)
								v_encoded_size[0] = (uint32_t)vurlkey[i].sRSA_ECC_ENCODED_DATA.size();
							else
								v_encoded_size.push_back((uint32_t)vurlkey[i].sRSA_ECC_ENCODED_DATA.size() );
						}
						else
						{
							v_encoded_size[riter] = (uint32_t)msg_size_produced;
						}

						vurlkey[i].rsa_ecc_encoded_data_pos = 0; // set later
						vurlkey[i].rsa_ecc_encoded_data_len = (uint32_t)vurlkey[i].sRSA_ECC_ENCODED_DATA.size();
               		}
					else
					{
						std::cerr << "ERROR ecc_key not found: " << ecc_key_at_iter << "  in " << local_ecc_other_db << std::endl;
						break;
					}

				} // for (size_t riter=0; riter < v.size; riter++)

				if (r)
				{
					if (v.size() > 1)
					{
						std::string new_URL = "[e]";
						for (size_t riter=0; riter < v.size(); riter++)
						{
							std::string ecc_key_at_iter = v[riter];
							new_URL += ecc_key_at_iter;
							new_URL += std::string(";");
							new_URL += std::to_string(v_encoded_size[riter]);
							new_URL += std::string(";");
						}
						if (new_URL.size() > URL_MAX_SIZE)
						{
							std::cerr << "ERROR resursive ecc too long: " << new_URL << std::endl;
							r = false;
						}
						else
						{
							vurlkey[i].set_url(new_URL);
							if (verbose)
                            	std::cout << "ECC Recursive NEW URL: " << new_URL << " " << new_URL.size() << std::endl;
						}
					}
				}
			}
        }
        else if (is_web)
        {
            rc = wget(s.data(), file.data(), verbose);
            if (rc!= 0)
            {
                std::cerr << "ERROR with wget, error code: " << rc << " url: " << s <<  " file: " << file << std::endl;
                r = false;
            }
        }
        else
        {
        }

		if (r)
		{
			cryptodata* pointer_datafile;
			if (is_rsa)
            {
                pointer_datafile = &rsa_key_data;
            }
			else if (is_ecc)
            {
                pointer_datafile = &ecc_key_data;
            }
            else if (is_histo)
            {
                pointer_datafile = &histo_key_data;
            }
			else if (is_local == false)
			{
                r = dataout_other.read_from_file(file);
                pointer_datafile = &dataout_other;
            }
            else
            {
                pointer_datafile = &dataout_local;
            }
            cryptodata& d = *pointer_datafile;

			if (r)
			{
                if (is_rsa)
                {
                    d.buffer.write(embedded_rsa_key.data(), (uint32_t)embedded_rsa_key.size());
                }
				else if (is_ecc)
                {
                    d.buffer.write(embedded_ecc_key.data(), (uint32_t)embedded_ecc_key.size());
                }
                else if (is_histo)
                {
                    d.buffer.write(histo_key.data(), (uint32_t)histo_key.size());

                    // key change to known index to the decryptor
                    vurlkey[i].set_url(std::string("[h]") + kout.data_sha[0]);
                }

                uint32_t databuffer_size = (uint32_t)d.buffer.size();
                vurlkey[i].key_size = perfect_key_size;

				if (databuffer_size >= perfect_key_size)
				{
					random_engine rd;
					if (verbose)
                    {
                        //std::cout << "get a random position in " << databuffer_size << " bytes of url file" <<  std::endl;
                    }

					uint32_t t = (uint32_t) (rd.get_rand() * (databuffer_size - perfect_key_size));
					vurlkey[i].key_fromH = (t / BASE);
					vurlkey[i].key_fromL = t - (vurlkey[i].key_fromH  * BASE);

                    if (verbose)
                    {
                        std::cout << "key_pos :"  << t << " ";
                        std::cout << "key_size:"  << vurlkey[i].key_size << " ";
                        std::cout <<  std::endl;
					}

                    Buffer* b = vurlkey[i].get_buffer(); // allocate
                    b->increase_size(perfect_key_size);
                    b->write(&d.buffer.getdata()[t], perfect_key_size, 0);

                    if (verbose)
                    {
                        show_summary(b->getdata(), perfect_key_size);
                    }
				}
				else
				{
                    if (verbose)
                    {
                        if ((is_rsa == false) && (is_ecc == false))
                        {
                            std::cout << "WARNING URL file size less than key size (padding remaining) "  << "key_pos=" << (int32_t)0 <<  std::endl;
                            std::cout << "WARNING Increase number of URL (or use bigger URL file size) for perfect security" <<  std::endl;
                        }
                    }

					vurlkey[i].key_fromH = 0;
					vurlkey[i].key_fromL = 0;

                    Buffer* b = vurlkey[i].get_buffer(); // allocate
                    b->increase_size(perfect_key_size);
                    b->write(&d.buffer.getdata()[0], databuffer_size, 0);

                    char c[1]; uint32_t rotate_pos;
					for( uint32_t j = databuffer_size; j< perfect_key_size; j++) // padding vurlkey[i].get_buffer() to perfect_key_size
					{
                        rotate_pos = j % databuffer_size;
						c[0] =d.buffer.getdata()[rotate_pos];
                        b->write(&c[0], 1, -1);
                    }

                    if (verbose)
                    {
                        show_summary(b->getdata(), perfect_key_size);
                    }
				}

				if      (i%6==0)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc;
				else if (i%6==1)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_ecb;
				else if (i%6==2)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb;
				else if (i%6==3)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH;
				else if (i%6==4)  vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_Salsa20;
				else              vurlkey[i].crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_IDEA;

				if (verbose)
                    std::cout << "crypto_algo: " << vurlkey[i].crypto_algo << std::endl;

                {
                    vurlkey[i].do_checksum_key(d);
                    if (verbose)
                    {
                        std::cout << "key extracted from data of size: " << d.buffer.size() << std::endl;
                    }
                }
            }
            else
            {
                std::cerr << "ERROR reading file: " << file << std::endl;
            }
		}

		//if (r)
		{
			if (keeping == false)
			{
				if (fileexists(file))
					std::remove(file.data());
			}
		}
		return r;
	}

    bool make_urlinfo_with_padding(size_t i)
	{
		bool r = true;

		Buffer temp(URLINFO_SIZE);
		temp.init(0);
		temp.writeUInt16(vurlkey[i].crypto_algo, -1);
		temp.writeUInt16(vurlkey[i].url_size, -1);
		temp.write(&vurlkey[i].url[0], URL_MAX_SIZE, -1);
		temp.write(&vurlkey[i].magic[0], 4, -1);
		temp.writeUInt16(vurlkey[i].key_fromH, -1);
		temp.writeUInt16(vurlkey[i].key_fromL, -1);
		temp.writeUInt32(vurlkey[i].key_size, -1);
		temp.write(&vurlkey[i].key[0], MIN_KEY_SIZE, -1);
		temp.write(&vurlkey[i].checksum[0], CHKSUM_SIZE, -1);
		temp.write(&vurlkey[i].checksum_data[0], CHKSUM_SIZE, -1);

		temp.writeUInt32(vurlkey[i].rsa_ecc_encoded_data_pad, -1);
		temp.writeUInt32(vurlkey[i].rsa_ecc_encoded_data_len, -1);
		temp.writeUInt32(vurlkey[i].rsa_ecc_encoded_data_pos, -1);

        if (shufflePerc > 0)
        {
            vurlkey[i].crypto_flags = 1;
            vurlkey[i].shuffle_perc = shufflePerc;
        }
        else
        {
            vurlkey[i].crypto_flags = 0;
            vurlkey[i].shuffle_perc = 0;
        }
		temp.writeUInt32(vurlkey[i].crypto_flags, -1);
		temp.writeUInt32(vurlkey[i].shuffle_perc, -1);

//		std::string s(vurlkey[i].url);
//		std::cout << "make_urlinfo_with_padding URL at i " << i <<" " << s << " " << s.size() << std::endl;
//		std::cout << "make_urlinfo_with_padding URL rsa_encoded_data_pad " << i <<" " << vurlkey[i].rsa_encoded_data_pad << " " << std::endl;
//		std::cout << "make_urlinfo_with_padding URL rsa_encoded_data_len " << i <<" " << vurlkey[i].rsa_encoded_data_len << " "  << std::endl;
//		std::cout << "make_urlinfo_with_padding URL rsa_encoded_data_pos " << i <<" " << vurlkey[i].rsa_encoded_data_pos << " "  << std::endl;

		for( size_t j = 0; j< URLINFO_SIZE; j++)
            vurlkey[i].urlinfo_with_padding[j] = temp.getdata()[j];

		return r;
	}

    bool encode_idea(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 8 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_idea data file must be multiple of 8 bytes idea: " << data_temp.buffer.size() << std::endl;
            return r;
		}
        if (data_temp.buffer.size() == 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_idea data file is empty " << std::endl;
            return r;
		}

		if (key_size % 16 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_idea key must be multiple of 16 bytes: " <<  key_size << std::endl;
            return r;
		}
        if (key_size == 0)
		{
            std::cerr << "ERROR encode_idea - key_size = 0 " << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 8;
		uint32_t nkeys  = key_size / 16;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() idea 8_16                 " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (8 bytes): " << nblock <<
                            ", number of keys (16 bytes): "  << nkeys  << ", shuffling: " << shufflePerc <<  "%" << std::endl;
        }

		uint8_t KEY[16+1];
		uint8_t DATA[8+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 8; j++)
                    {
                        c = data_temp.buffer.getdata()[8*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 8; j++)
                    {
                        c = data_temp_next.buffer.getdata()[8*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                idea algo;
                algo.IDEA(DATA, KEY, true);

                data_temp_next.buffer.write((char*)&DATA[0], (uint32_t)8, -1);
            }
        }

		return r;
	}


    bool encode_salsa20(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 64 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_salsa20 data file must be multiple of 64 bytes: " << data_temp.buffer.size() << std::endl;
            return r;
		}
        if (data_temp.buffer.size() == 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_salsa20 data file is empty " << std::endl;
            return r;
		}

		if (key_size % 32 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_salsa20 key must be multiple of 32 bytes: " <<  key_size << std::endl;
            return r;
		}
        if (key_size == 0)
		{
            std::cerr << "ERROR encode_salsa20 - key_size = 0 " << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 64;
		uint32_t nkeys  = key_size / 32;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() salsa20 32_64             " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (64 bytes): " << nblock <<
                            ", number of keys (32 bytes): "   << nkeys  << ", shuffling: " << shufflePerc <<  "%" << std::endl;
        }

		uint8_t KEY[32+1];
		uint8_t DATA[64+1];
		uint8_t enc[64+1];
		uint32_t key_idx = 0;
		uint8_t iv[8]  = {0x12, 0x01, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde};

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_temp.buffer.getdata()[64*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[64] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_temp_next.buffer.getdata()[64*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[64] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 32; j++)
                {
                    c = key[32*key_idx + j];
                    KEY[j] = c;
                }
                KEY[32] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                ucstk::Salsa20 s20(KEY);
                s20.setIv(iv);
                s20.processBlocks(DATA, enc, 1);

                data_temp_next.buffer.write((char*)&enc[0], (uint32_t)64, -1);
            }
        }

		return r;
	}

    bool encode_twofish(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 16 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "encode_twofish encoding file must be multiple of 16 bytes: "  << data_temp.buffer.size() << std::endl;
			return false;
		}
		if (key_size == 0)
		{
            std::cerr << "ERROR encode_twofish - key_size = 0 "  << std::endl;
            return false;
        }
        if (key_size % 16 != 0)
		{
            std::cerr << "ERROR encode_twofish - key_size must be 16x: " <<  key_size << std::endl;
            return false;
        }
        if (data_temp.buffer.size() == 0)
		{
            std::cerr << "ERROR encode_twofish - data size is 0 " << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		int rr = 0;
		if (s_Twofish_initialise == false)
		{
            rr = Twofish_initialise();
            if (rr < 0)
            {
                std::cout << "Error with Twofish_initialise: " << rr << std::endl;
                r = false;
                return r;
            }
            s_Twofish_initialise = true;
        }

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() twofish 16_16             " <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << ", shuffling: " << shufflePerc <<  "%" << std::endl;
        }

		Twofish_Byte KEY[16+1];
		Twofish_Byte DATA[16+1];
		Twofish_Byte out[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp_next.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;


                Twofish_key xkey;
                rr = Twofish_prepare_key( KEY, 16, &xkey );
                if (rr < 0)
                {
                    std::cerr << "ERROR Twofish_prepare_key: " << rr << std::endl;
                    r = false;
                    break;
                }

                Twofish_encrypt(&xkey, DATA, out);
                data_temp_next.buffer.write((char*)&out[0], (uint32_t)16, -1);
            }
        }

		return r;
	}

	bool encode_binaes16_16(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next,
                            CRYPTO_ALGO_AES aes_type)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 16 != 0)
		{
            r = false;
            std::cerr << "ERROR encode_binaes16_16 " << "encoding file must be multiple of 16 bytes: " << data_temp.buffer.size() << std::endl;
			return false;
		}
        if (data_temp.buffer.size() == 0)
		{
            std::cerr << "ERROR encode_binaes16_16 - data size is 0 " << std::endl;
            return false;
        }

        if (key_size == 0)
		{
            std::cerr << "ERROR encode_binaes16_16 - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (key_size % 16 != 0)
		{
            std::cerr << "ERROR encode_binaes16_16 - key_size must be 16x: " <<  key_size << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_temp.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_temp.buffer.size() > 0)
		{
            if (key_size > data_temp.buffer.size() )
            {
                nround = key_size / data_temp.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() binAES 16_16 - aes_type: " << (int)aes_type <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << ", shuffling: " << shufflePerc <<  "%" << std::endl;
        }

		unsigned char KEY[16+1];
		unsigned char DATA[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (r == false)
                break;

            if (roundi > 0)
                data_temp_next.buffer.seek_begin();

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_temp_next.buffer.getdata()[16*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[16] = 0; // Data must be 128 bits long
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16] = 0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                unsigned int plainLen = 16 * sizeof(unsigned char);

                if (aes_type == CRYPTO_ALGO_AES::ECB)
                {
                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto e = aes.EncryptECB(DATA, plainLen, KEY);

                    data_temp_next.buffer.write((char*)&e[0], (uint32_t)16, -1);
                    delete []e;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CBC)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto e = aes.EncryptCBC(DATA, plainLen, KEY, iv);

                    data_temp_next.buffer.write((char*)&e[0], (uint32_t)16, -1);
                    delete []e;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CFB)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto e = aes.EncryptCFB(DATA, plainLen, KEY, iv);

                    data_temp_next.buffer.write((char*)&e[0], (uint32_t)16, -1);
                    delete []e;
                }
                else
                {
                    std::cerr << "ERROR unsupportes AES type " << (int)aes_type << std::endl;
                    r = false;
                    break;
                }
            }
        }

		return r;
	}

	bool encode_binDES(cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;
		char c;

		if (data_temp.buffer.size() % 4 != 0)
		{
            r = false;
            std::cerr << "ERROR binDES -  encoding file must be multiple of 4 bytes: " << data_temp.buffer.size() << std::endl;
			return false;
		}
        if (data_temp.buffer.size() == 0)
		{
            std::cerr << "ERROR binDES - data size is 0 " << std::endl;
            return false;
        }

        if (key_size == 0)
		{
            std::cerr << "ERROR binDES - key_size = 0 " << std::endl;
            return false;
        }
        if (key_size % 4 != 0)
		{
            std::cerr << "ERROR binDES - key_size must be 4x: " <<  key_size << std::endl;
            return false;
        }

        // BINARY DES is multiple of 4
		uint32_t nblock = data_temp.buffer.size() / 4;
		uint32_t nkeys  = key_size / 4;

		if (verbose)
		{
            std::cout.flush();
            std::cout <<    "Encryptor encode() binDES - " <<
                            "number of blocks (4 bytes): " << nblock <<
                            ", number of keys (4 bytes): " << nkeys  << ", shuffling: " << shufflePerc <<  "%" << std::endl;
        }

		char KEY[4];
		char DATA[4];
		std::string data_encr;

		uint32_t key_idx = 0;
		for(size_t blocki = 0; blocki < nblock; blocki++)
		{
            for(size_t j = 0; j < 4; j++)
            {
                c = data_temp.buffer.getdata()[4*blocki + j];
                DATA[j] = c;
            }

            for(size_t j = 0; j < 4; j++)
            {
                c = key[4*key_idx + j];
                KEY[j] = c;
            }
            key_idx++;
            if (key_idx >= nkeys) key_idx=0;

            DES des(KEY);
            data_encr = des.encrypt_bin(DATA, 4);
            data_temp_next.buffer.write(data_encr.data(), (uint32_t)data_encr.size(), -1); // 8 bytes!
        }

		return r;
	}

	//------------------------------------------
	// encode() data_temp => data_temp_next
	//------------------------------------------
    bool encode( size_t iter, size_t NITER, uint16_t crypto_algo, uint32_t crypto_flags, uint32_t shufflePerc,
                 cryptodata& data_temp, const char* key, uint32_t key_size, cryptodata& data_temp_next)
	{
		bool r = true;

		if (crypto_flags & 1)
		{
			cryptoshuffle sh(verbose);
			r = sh.shuffle(data_temp.buffer, key, key_size, shufflePerc);

			if (r == false)
			{
				std::cerr << "ERROR with shuffle of data " <<  iter << std::endl;
				return false;
			}
		}

		if ((iter==0) || (iter==NITER))
		{
            // DES double data size
            // return encode_binDES( data_temp, key, key_size, data_temp_next);
            return encode_salsa20(data_temp, key, key_size, data_temp_next);
		}
		else
		{
            if (iter-1 >= vurlkey.size())
            {
                std::cerr << "ERROR mismatch iter out of range " <<  iter-1 << std::endl;
				return false;
            }
            else if ((crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_ecb) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_Salsa20) &&
                     (crypto_algo != (uint16_t)CRYPTO_ALGO::ALGO_IDEA)
                     )
            {
                std::cerr << "WARNING mismatch algo at iter (using default) " <<  iter-1 << std::endl;
            }

            if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_TWOFISH)
            {
                return encode_twofish(data_temp, key, key_size, data_temp_next);
            }
            else if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_Salsa20)
            {
                return encode_salsa20(data_temp, key, key_size, data_temp_next);
            }
            else if (crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_IDEA)
            {
                return encode_idea(data_temp, key, key_size, data_temp_next);
            }
            else
            {
                CRYPTO_ALGO_AES aes_type = CRYPTO_ALGO_AES::ECB;
                if (crypto_algo      == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cbc) aes_type = CRYPTO_ALGO_AES::CBC;
                else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_16_16_cfb) aes_type = CRYPTO_ALGO_AES::CFB;

                return encode_binaes16_16(data_temp, key, key_size, data_temp_next, aes_type);
            }
        }

		return r;
	}

    bool encrypt(bool allow_empty_url = false)
    {
        bool r = true;

        bool empty_puzzle = false;
        if (filename_puzzle.size() ==  0)
        {
            empty_puzzle = true;
        }

        if (filename_msg_data.size() ==  0)
        {
            std::cerr << "ERROR empty msg_data filename " <<  std::endl;
            return false;
        }

        if (empty_puzzle == false)
        {
            if (fileexists(filename_puzzle) == false)
            {
                std::cerr << "ERROR missing puzzle file: " << filename_puzzle <<  std::endl;
                return false;
            }
        }

        if (fileexists(filename_msg_data) == false)
        {
            std::cerr << "ERROR missing msg file: " << filename_msg_data <<  std::endl;
            return false;
        }

        // URLS  read
        if (filename_urls.size() > 0)
        {
            if (fileexists(filename_urls))
            {
                if (read_file_urls(filename_urls) == false)
                {
                    std::cerr << "ERROR " << "reading urls: " << filename_urls << std::endl;
                    return false;
                }

                if (allow_empty_url == false)
                {
                    if (vurlkey.size() == 0)
                    {
                        std::cerr << "ERROR " << "url empty in file: " << filename_urls << std::endl;
                        return false;
                    }
                }
            }
            else
            {
            }
        }

        if (empty_puzzle == false)
        {
            if (puz.read_from_file(filename_puzzle, true) == false)
            {
                std::cerr << "ERROR " << " reading puzzle file: " << filename_puzzle << std::endl;
                return false;
            }
            if (puz.puz_data.buffer.size() == 0)
            {
                std::cerr << "ERROR " << "puzzle file empty: " << filename_puzzle << std::endl;
                return false;
            }
        }
        else
        {
            puz.read_from_empty_puzzle();
        }


		if (puz.is_all_answered() == false)
        {
            std::cerr << "ERROR " << "puzzle not fully answered " << std::endl;
            return false;
        }

        // before removal of answer
        if (filename_full_puzzle.size() > 0)
        {
            if (puz.save_to_file(filename_full_puzzle) == false)
            {
                std::cerr << "ERROR " << "saving full puzzle: " << filename_full_puzzle << std::endl;
                return false;
            }
        }

        // before removal of answer
        Buffer puz_key_full(10000);

        puz.make_key(puz_key_full);
        if (puz_key_full.size()== 0)
        {
            std::cerr << "ERROR " << "reading puzzle key in file: " << filename_full_puzzle << std::endl;
            return false;
        }

        // removal of answer
        if (puz.make_partial() == false)
        {
            std::cerr << "ERROR " << "making partial puzzle" << std::endl;
            return false;
        }

        // qa puzzle - not the full
        // after removal of answer
        Buffer qa_puz_key(puz_key_full.size());
        puz.make_key(qa_puz_key);
        if (qa_puz_key.size()== 0)
        {
            std::cerr << "ERROR " << "making qa puzzle key" << std::endl;
            return false;
        }

        // after removal of answer
        if (empty_puzzle == false)
        {
            if (puz.save_to_file(filename_partial_puzzle) == false)
            {
                std::cerr << "ERROR " << "saving puzzle: " << filename_partial_puzzle << std::endl;
                return false;
            }
        }

        // -----------------------
        // DATA prepare
        // -----------------------
        r = pre_encode(filename_msg_data, msg_data);
        if (r==false)
        {
            return r;
        }

        msg_input_size = msg_data.buffer.size();
        NURL_ITERATIONS = (int32_t)vurlkey.size();
		if (NURL_ITERATIONS >= 1)
		{
            perfect_key_size = ((int32_t)msg_input_size) / NURL_ITERATIONS; // ignore extra and ignore first encoding
            if (perfect_key_size % MIN_KEY_SIZE != 0)
            {
                perfect_key_size += MIN_KEY_SIZE - (perfect_key_size % MIN_KEY_SIZE);
            }
		}

		if (perfect_key_size < MIN_KEY_SIZE) perfect_key_size = MIN_KEY_SIZE;
		perfect_key_size = perfect_key_size * key_size_factor;

        if (verbose)
        {
            std::cout << "msg_input_size = " << msg_input_size;
            std::cout << ", number of URL keys = " << NURL_ITERATIONS;
            std::cout << ", key_size_factor = " << key_size_factor;
            std::cout << ", perfect_key_size (* key_size_factor) = " << perfect_key_size <<
                         ", total keys size: " << NURL_ITERATIONS * perfect_key_size + puz_key_full.size() << std::endl;
        }

        //--------------------------------
        // GET URL KEYS INFO
        //--------------------------------
        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (verbose)
            {
                std::cout.flush();
                std::cout << "\nencryptor making keys - iteration: " << i << std::endl;
            }

            if (make_urlkey_from_url(i) == false)
            {
                std::cerr << "ERROR " << "extracting url info, url index: " << i << std::endl;
                return false;
            }
            if (make_urlinfo_with_padding(i) == false)
            {
                std::cerr << "ERROR " << "making url info, url index: " << i <<std::endl;
                return false;
            }


			{
				for(size_t ii=0; ii<MIN_KEY_SIZE; ii++)
					vurlkey[i].key[ii] = 0;
			}
        }

        //--------------------------------
        // Data to encrypt data_temp
        //--------------------------------
        if (msg_data.copy_buffer_to(data_temp)== false)
        {
            std::cerr << "ERROR " << "reading copying msg file: " << filename_msg_data <<std::endl;
            return false;
        }

        int16_t PADDING = 0;
        auto sz_msg = data_temp.buffer.size();
        if (verbose)
        {
            std::cout << "MESSAGE is " << sz_msg  << " bytes"<< std::endl;
        }

        if (sz_msg % PADDING_MULTIPLE != 0)
        {
            int16_t n = PADDING_MULTIPLE - (sz_msg % PADDING_MULTIPLE);
            if (verbose)
            {
                if (n > 0)
                    std::cout << "Padding msg with bytes: " << n  << std::endl;
            }

            PADDING = n;
            char c[1] = {' '};
            for(int16_t i= 0; i< n; i++)
                data_temp.buffer.write(&c[0], 1, -1);
        }

        //--------------------------------
        // URL KEYS iterations: 0 to N-1
        //--------------------------------
		// encode(Data,          key1) => Data1 // urlkey1=>key1
        // encode(Data1+urlkey1, key2) => Data2
        // encode(Data2+urlkey2, key3) => Data3
        // ...
        // encode(DataN-1+urlkeyN-1, keyN) => DataN
        for(size_t i=0; i<vurlkey.size(); i++)
        {
            if (i==0)
            {
                // skip msg_data already read into data_temp
            }

            if (i>0)
            {
                vurlkey[i-1].do_checksum_data(data_temp);

                // Update urlinfo
                if (make_urlinfo_with_padding(i-1) == false)
                {
                    std::cerr << "ERROR " << "making url info - url index: " << i-1 <<std::endl;
                    return false;
                }

                // RSA or ECC data
				if (vurlkey[i-1].rsa_ecc_encoded_data_len > 0)
				{
					vurlkey[i-1].rsa_ecc_encoded_data_pos = data_temp.buffer.size();

					if (vurlkey[i-1].rsa_ecc_encoded_data_len % PADDING_MULTIPLE != 0)
					{
						auto p = PADDING_MULTIPLE - (vurlkey[i-1].rsa_ecc_encoded_data_len % PADDING_MULTIPLE);
						char c[1] = {0};
						vurlkey[i-1].rsa_ecc_encoded_data_pad = p;
						for(size_t j=0; j<p; j++)
						{
							data_temp.append(&c[0], 1);
						}
                    }
					else
					{
						vurlkey[i-1].rsa_ecc_encoded_data_pad = 0;
					}

					// Update urlinfo
					if (make_urlinfo_with_padding(i-1) == false)
					{
						std::cerr << "ERROR " << "making url info - url index: " << i-1 <<std::endl;
						return false;
					}

					// APPEND RSA_ENCODED_DATA
                    data_temp.append(vurlkey[i-1].sRSA_ECC_ENCODED_DATA.data(), vurlkey[i-1].rsa_ecc_encoded_data_len);
				}

                // APPEND URLINFO
                data_temp.append(&vurlkey[i-1].urlinfo_with_padding[0], URLINFO_SIZE);
            }

            data_temp_next.clear_data();

            //--------------------------------------------------------
            // encode() data_temp => data_temp_next
            //--------------------------------------------------------
            encode( i, vurlkey.size(), vurlkey[i].crypto_algo,
					vurlkey[i].crypto_flags, vurlkey[i].shuffle_perc,
                    data_temp,
                    &vurlkey[i].get_buffer()->getdata()[0], vurlkey[i].key_size,
                    data_temp_next);

            data_temp.buffer.swap_with(data_temp_next.buffer);
            data_temp_next.erase();

        } //for(size_t i=0; i<vurlkey.size(); i++)

        //--------------------------------
        // LAST ITER: encode(DataN+urlkeyN+Niter, puz_key) => DataFinal
        //--------------------------------
        if (vurlkey.size()>0)
        {
            vurlkey[vurlkey.size()-1].do_checksum_data(data_temp);

            // Update urlinfo
            if (make_urlinfo_with_padding(vurlkey.size()-1) == false)
            {
                std::cerr << "ERROR " << "making url info - url index: " << vurlkey.size()-1 <<std::endl;
                return false;
            }


			// RSA DATA
			vurlkey[vurlkey.size()-1].rsa_ecc_encoded_data_pos = data_temp.buffer.size();
			if (vurlkey[vurlkey.size()-1].rsa_ecc_encoded_data_len > 0)
			{
				// multiple PADDING_MULTIPLE
				if (vurlkey[vurlkey.size()-1].rsa_ecc_encoded_data_len % PADDING_MULTIPLE != 0)
				{
                    auto p = PADDING_MULTIPLE - (vurlkey[vurlkey.size()-1].rsa_ecc_encoded_data_len % PADDING_MULTIPLE);
                    char c[1] = {0};
                    vurlkey[vurlkey.size()-1].rsa_ecc_encoded_data_pad = p;
                    for(size_t j=0; j<p; j++)
                    {
                        data_temp.append(&c[0], 1);
                    }
				}
				else
				{
					vurlkey[vurlkey.size()-1].rsa_ecc_encoded_data_pad = 0;
				}

				// Update
				if (make_urlinfo_with_padding(vurlkey.size()-1) == false)
				{
					std::cerr << "ERROR " << "making url info - url index: " << vurlkey.size()-1 <<std::endl;
					return false;
				}

				// APPEND RSA_ENCODED_DATA
				data_temp.append(vurlkey[vurlkey.size()-1].sRSA_ECC_ENCODED_DATA.data(), vurlkey[vurlkey.size()-1].rsa_ecc_encoded_data_len);
			}

            // APPEND URLINFO
            data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
        }

        uint32_t crc_full_puz_key= 0;
        {
            CRC32 crc;
            crc.update(&puz_key_full.getdata()[0], puz_key_full.size());
            crc_full_puz_key = crc.get_hash();
        }

        Buffer temp(PADDING_MULTIPLE); // 64x
		temp.init(0);
		temp.writeUInt32(crc_full_puz_key, PADDING_MULTIPLE - 8);
        temp.writeUInt16(PADDING, PADDING_MULTIPLE - 4);
		temp.writeUInt16((uint16_t)vurlkey.size() + 1, PADDING_MULTIPLE - 2); // Save number of iterations
        data_temp.append(temp.getdata(), PADDING_MULTIPLE);

        //--------------------------------------------------------
        // encode() data_temp => data_temp_next
        //--------------------------------------------------------
        encode( vurlkey.size(), vurlkey.size(), (uint16_t)CRYPTO_ALGO::ALGO_BIN_DES, 0, 0,
                data_temp, puz_key_full.getdata(), puz_key_full.size(), data_temp_next);

        data_temp_next.buffer.writeUInt32(crc_full_puz_key, -1);    // PLAIN

        if (verbose)
        {
            std::cout << "data encrypted size: "  << data_temp_next.buffer.size() << std::endl;
            std::cout << "qa_puz_key size:     "  << qa_puz_key.size() << std::endl;
        }

        //--------------------------------------------------------
        // post_encode()
        //--------------------------------------------------------
		if (converter > 0)
		{
			if (verbose)
			{
				std::cout << "post encode..." << std::endl;
			}

			std::string new_output_filename;
			bool r = post_encode(data_temp_next, filename_encrypted_data, encrypted_data, new_output_filename); // Convert and  SAVE
			if (r == false)
			{
				std::cout << "ERROR post_encode to "  << new_output_filename << std::endl;
				return false; // disable -pgn next time
			}
			else
			{
				filename_encrypted_data = new_output_filename; // override
				if (verbose)
				{
					std::cout << "saved to "  << new_output_filename << std::endl;
				}
			}
		}
		else
		{
			data_temp_next.copy_buffer_to(encrypted_data);
			encrypted_data.save_to_file(filename_encrypted_data);   // SAVE
			if (verbose)
			{
				std::cout << "saved to "  << filename_encrypted_data << std::endl;
			}
		}

		if (folder_my_private_hh.size() > 0)
		{
			std::string local_histo_db = folder_my_private_hh + HHKEY_MY_PRIVATE_ENCODE_DB;
			bool result;
			history_key hkey(encrypted_data, local_histo_db, result);
            if (result)
            {
				uint32_t out_seq;
				result = get_next_seq(out_seq, local_histo_db);
				if (result)
				{
					hkey.update_seq(out_seq);
                	save_histo_key(hkey, local_histo_db);
                	if (verbose)
                        std::cout << "history sequence saved: "  << out_seq << std::endl;
				}
            }
		}

		return true;
    }

	bool 				cfg_parse_result = true;
    crypto_cfg          cfg;
    cryptodata          urls_data;
    cryptodata          msg_data;
    puzzle              puz;
    cryptodata          encrypted_data;

    std::vector<urlkey> vurlkey;
    cryptodata          data_temp;
    cryptodata          data_temp_next;

    std::string filename_cfg;
    std::string filename_urls;
    std::string filename_msg_data;
    std::string filename_puzzle;
    std::string filename_partial_puzzle;
    std::string filename_full_puzzle;
    std::string filename_encrypted_data;
    std::string staging;
    std::string folder_local;
    std::string folder_my_private_rsa;
	std::string folder_other_public_rsa;
    std::string folder_my_private_ecc;
    std::string folder_other_public_ecc;
    std::string folder_my_private_hh;
    std::string folder_other_public_hh;

    bool verbose;
    bool keeping;
    std::string encryped_ftp_user;
    std::string encryped_ftp_pwd;
    std::string known_ftp_server;
	bool use_gmp;
	bool self_test;
    int staging_cnt=0;

    size_t  msg_input_size = 0;
    int32_t NURL_ITERATIONS = 0;
	uint32_t perfect_key_size = 0;
	long key_size_factor = 1;
	uint32_t shufflePerc = 0;

    bool auto_flag = false;
    std::string auto_options;

	uint32_t converter = 0; // 1==PNG
	cryptodata_list datalist;

	bool post_encode(cryptodata& indata, const std::string& filename, cryptodata& out_encrypted_data, std::string& new_output_filename)
	{
		bool r = true;
		new_output_filename = filename;

		if (converter == 1) // 1==PNG
		{
			// NEED an envelop for data so size get to square for png
			cryptodata_list newdatalist(verbose);
			newdatalist.set_converter(converter); // PNG padding
			newdatalist.add_data(&indata, filename, filename, CRYPTO_FILE_TYPE::RAW);

			// out_encrypted_data is a working buffer
			r = newdatalist.create_header_trailer_buffer(out_encrypted_data);
			if (r==false)
			{
				std::cerr << "ERROR " << " post_encode error with create_header_trailer_buffer " << std::endl;
				return false;
			}
			if (verbose) newdatalist.header.show();

			std::string filename_tmp_envelop = filename +".temp";
			out_encrypted_data.save_to_file(filename_tmp_envelop);
			if (verbose) std::cout << "INFO " << "filename_tmp_envelop: " << filename_tmp_envelop <<std::endl;

			new_output_filename = filename + ".png";
			converter::pgn_converter png;
			int cr = png.binaryToPng(filename_tmp_envelop, new_output_filename); // SAVE as PGN
			if (cr != 0)
			{
				std::cerr << "ERROR " << "converting to file: " << new_output_filename <<std::endl;
				if (fileexists(filename_tmp_envelop))
					std::remove(filename_tmp_envelop.data());
				return false;
			}
			if (fileexists(filename_tmp_envelop))
				std::remove(filename_tmp_envelop.data());
		}
		else
		{
			indata.copy_buffer_to(out_encrypted_data);
			out_encrypted_data.save_to_file(filename);   // SAVE
			if (verbose)
			{
				std::cout << "saved to "  << filename << std::endl;
			}
		}
		return r;
	}

    // pre encode() [if auto flag, export public keys and satus other]
	bool pre_encode(const std::string& filename, cryptodata& out_data) // TODO ? local folder ...
	{
        datalist.verbose = verbose;
        bool r = true;

        if (USE_AUTO_FEATURE == false)  // old way
        {
            r = out_data.read_from_file(filename);
            if (r == false)
            {
                std::cerr << "ERROR " << "reading file: " << filename <<std::endl;
                return false;
            }
            return true;
        }

        // add message
        cryptodata* msg_data = nullptr;
        datalist.add_data(msg_data, filename, filename, CRYPTO_FILE_TYPE::RAW); // same name??

        if (!auto_flag)
        {
			std::cout << "!auto_flag" << std::endl;
        }
        else
        {
			// my public keys to export
            std::vector<keymgr::public_key_desc_exporting> vpubkeys;
            r = keymgr::export_public_keys( vpubkeys,
                                            folder_my_private_rsa,
                                            folder_my_private_ecc,
                                            folder_my_private_hh,
                                            verbose);
            if (r==false)
            {
                return false;
            }

            for(size_t i=0;i <vpubkeys.size(); i++)
            {
                datalist.add_data(vpubkeys[i].buffer, vpubkeys[i].public_filename, vpubkeys[i].public_other_short_filename, vpubkeys[i].filetype);
            }


			// status other public keys to export
			std::vector<keymgr::status_key_desc_exporting> vpubstatuskeys;
            r = keymgr::export_public_status_keys( 	vpubstatuskeys,
													folder_other_public_rsa,
													folder_other_public_ecc,
													folder_other_public_hh,
													verbose);
            if (r==false)
            {
                return false;
            }

            for(size_t i=0;i <vpubstatuskeys.size(); i++)
            {
                datalist.add_data(vpubstatuskeys[i].buffer, vpubstatuskeys[i].public_filename, vpubstatuskeys[i].public_other_short_filename, vpubstatuskeys[i].filetype);
            }

        }

        r = datalist.create_header_trailer_buffer(out_data);
        if (r==false)
        {
            return false;
        }

        return r;
	}
};

}

#endif
