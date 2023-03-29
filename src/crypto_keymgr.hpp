#ifndef CRYPTO_KEYMGR_H_INCLUDED
#define CRYPTO_KEYMGR_H_INCLUDED

#include "crypto_const.hpp"
#include "crypto_ecckey.hpp"
#include "data.hpp"
#include "crypto_file.hpp"
#include "crypto_key_parser.hpp"
#include "random_engine.hpp"
#include "crc32a.hpp"
#include "c_plus_plus_serializer.h"

namespace cryptoAL
{
namespace keymgr
{
    struct public_key_desc_exporting
    {
        std::string         path_private_db;
        std::string         public_filename;
        std::string         public_other_short_filename;
        CRYPTO_FILE_TYPE    filetype;
        cryptodata*         buffer = nullptr;

        public_key_desc_exporting(const std::string& f, CRYPTO_FILE_TYPE t)
            :   path_private_db(f),
                filetype(t)
        {
            if (t == CRYPTO_FILE_TYPE::RSA_PUBLIC)
            {
                public_filename = path_private_db + RSA_MY_PUBLIC_DB;
                public_other_short_filename = RSA_OTHER_PUBLIC_DB;
            }
            else if (t == CRYPTO_FILE_TYPE::ECC_PUBLIC)
            {
                public_filename = path_private_db + ECCKEY_MY_PUBLIC_DB;
                public_other_short_filename = ECCKEY_OTHER_PUBLIC_DB;
            }
			else if (t == CRYPTO_FILE_TYPE::ECC_DOMAIN)
            {
                public_filename = path_private_db + ECC_DOMAIN_PUBLIC_DB;
                public_other_short_filename = ECC_DOMAIN_OTHER_DB;
            }
            else if (t == CRYPTO_FILE_TYPE::HH_PUBLIC)
            {
                public_filename = path_private_db + HHKEY_MY_PUBLIC_DECODE_DB; 	// reading the exported file
                public_other_short_filename = HHKEY_OTHER_PUBLIC_DECODE_DB;		// remote name
            }
		}
    };

	struct status_key_desc_exporting
    {
        std::string         path_other_public_db;
        std::string         public_filename;
        std::string         public_other_short_filename;
        CRYPTO_FILE_TYPE    filetype;
        cryptodata*         buffer = nullptr;

        status_key_desc_exporting(const std::string& f, CRYPTO_FILE_TYPE t)
            :   path_other_public_db(f),
                filetype(t)
        {
			if (t == CRYPTO_FILE_TYPE::RSA_KEY_STATUS)
			{
				public_filename = path_other_public_db + RSA_OTHER_STATUS_DB;
                public_other_short_filename = RSA_MY_STATUS_DB;
			}
			else if (t == CRYPTO_FILE_TYPE::ECC_KEY_STATUS)
			{
				public_filename = path_other_public_db + ECC_OTHER_STATUS_DB;
                public_other_short_filename = ECC_MY_STATUS_DB;
			}
			else if (t == CRYPTO_FILE_TYPE::ECC_DOM_STATUS)
			{
				public_filename = path_other_public_db + ECCDOM_OTHER_STATUS_DB;
                public_other_short_filename = ECCDOM_MY_STATUS_DB;
			}
			else if (t == CRYPTO_FILE_TYPE::HH_KEY_STATUS)
			{
				public_filename = path_other_public_db + HH_OTHER_STATUS_DB;
                public_other_short_filename = HH_MY_STATUS_DB;
			}
		}
    };

	bool delete_public_keys_marked_for_deleting(const std::string& path_public_db, CRYPTO_FILE_TYPE t, bool& key_deleted, bool verbose=false)
	{
		bool r = true;
		key_deleted = false;
		verbose=verbose;

		if (t == CRYPTO_FILE_TYPE::RSA_PUBLIC)
        {
		    std::string fileDB = path_public_db + RSA_OTHER_PUBLIC_DB;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_public;

			bool ok = true;
			if (cryptoAL::fileexists(fileDB) == false)
			{
				std::cerr << "WARNING no file: " << fileDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
                {
                    std::ifstream infile;
                    infile.open(fileDB, std::ios_base::in);
                    infile >> bits(map_rsa_public);
                    infile.close();
				}

				for(auto& [keyname, k] : map_rsa_public)
				{
					if (k.deleted == true)
					{
						// delete
						key_deleted = true;
						map_rsa_public.erase(keyname);

					}
				}

				if (key_deleted == true)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(fileDB + ".bck", std::ios_base::out);
						outfile << bits(map_rsa_public);
						outfile.close();
					}

					// save private
					{
                        std::ofstream out;
                        out.open(fileDB, std::ios_base::out);
                        out << bits(map_rsa_public);
                        out.close();
					}
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::ECC_PUBLIC)
        {
		    std::string fileDB = path_public_db + ECCKEY_OTHER_PUBLIC_DB;
			std::map< std::string, ecc_key > map_ecc_public;

			bool ok = true;
			if (cryptoAL::fileexists(fileDB) == false)
			{
				std::cerr << "WARNING no file: " << fileDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
                {
                    std::ifstream infile;
                    infile.open(fileDB, std::ios_base::in);
                    infile >> bits(map_ecc_public);
                    infile.close();
				}

				for(auto& [keyname, k] : map_ecc_public)
				{
					if (k.deleted == true)
					{
						// delete
						key_deleted = true;
						map_ecc_public.erase(keyname);

					}
				}

				if (key_deleted == true)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(fileDB + ".bck", std::ios_base::out);
						outfile << bits(map_ecc_public);
						outfile.close();
					}

					// save private
					{
                        std::ofstream out;
                        out.open(fileDB, std::ios_base::out);
                        out << bits(map_ecc_public);
                        out.close();
					}
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::ECC_DOMAIN)
        {
		}
		else if (t == CRYPTO_FILE_TYPE::HH_PUBLIC)
        {
		    std::string fileDB = path_public_db + HHKEY_OTHER_PUBLIC_DECODE_DB; //??
			std::map< std::string, ecc_key > map_hh_public;

			bool ok = true;
			if (cryptoAL::fileexists(fileDB) == false)
			{
				std::cerr << "WARNING no file: " << fileDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
                {
                    std::ifstream infile;
                    infile.open(fileDB, std::ios_base::in);
                    infile >> bits(map_hh_public);
                    infile.close();
				}

				for(auto& [keyname, k] : map_hh_public)
				{
					if (k.deleted == true)
					{
						// delete
						key_deleted = true;
						map_hh_public.erase(keyname);

					}
				}

				if (key_deleted == true)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(fileDB + ".bck", std::ios_base::out);
						outfile << bits(map_hh_public);
						outfile.close();
					}

					// save private
					{
                        std::ofstream out;
                        out.open(fileDB, std::ios_base::out);
                        out << bits(map_hh_public);
                        out.close();
					}
				}
			}
		}
		return r;
	}

	bool merge_other_ecc_domain(const std::string& path_ecc_private_db, const std::string& path_ecc_other_db, bool& key_merged, bool verbose=false)
	{
		bool r = true;

		std::string filePrivateECCDB = path_ecc_private_db  + ECC_DOMAIN_DB;
  		std::string fileStatusECCDB  = path_ecc_other_db    + ECC_DOMAIN_OTHER_DB;

		std::map< std::string, ecc_domain > map_eccdom_private;
		std::map< std::string, ecc_domain > map_eccdom_other;

		bool ok = true;
		if (cryptoAL::fileexists(fileStatusECCDB) == false)
		{
			ok = false;
		}
		else if (cryptoAL::fileexists(filePrivateECCDB) == false)
		{
			// ok will create one...
		}

		if (ok)
		{
			if (cryptoAL::fileexists(filePrivateECCDB) == true)
			{
				std::ifstream infile;
				infile.open(filePrivateECCDB, std::ios_base::in);
				infile >> bits(map_eccdom_private);
				infile.close();
			}

			{
				std::ifstream infile;
				infile.open(fileStatusECCDB, std::ios_base::in);
				infile >> bits(map_eccdom_other);
				infile.close();
			}

			for(auto& [keyname, k] : map_eccdom_other)
			{
				// If not found
				if (map_eccdom_private.find(keyname) == map_eccdom_private.end())
				{
					if (k.deleted == false)
					{
						ecc_domain key_public;
						key_public.create_from(k); // default flags

						std::string computename = key_public.name();
						if (computename == keyname)
						{
                            // TODO extra validation is it a valid curve...
                            // TODO config flag if accepting remote domain automatically without validation....
                            // TODO flag pending checking curve...long time...

                            key_public.confirmed = true;
							key_public.dt_confirmed = cryptoAL::get_current_time_and_date();

							key_merged = true;
							map_eccdom_private.insert(std::make_pair(keyname, key_public));

							if (verbose)
							{
								std::cout << "New ECC DOMAIN key has been ADDED: " << keyname << std::endl;
							}
						}
						else
						{
							std::cout << "WARNING cannot add invalid ECC DOMAIN key name: " << keyname << std::endl;
						}
					}
				}
			}

			if (key_merged == true)
			{
				// backup
				if (cryptoAL::fileexists(filePrivateECCDB) == true)
				{
					std::ofstream outfile;
					outfile.open(filePrivateECCDB + ".bck", std::ios_base::out);
					outfile << bits(map_eccdom_private);
					outfile.close();
				}

				// save private
				{
					std::ofstream out;
					out.open(filePrivateECCDB, std::ios_base::out);
					out << bits(map_eccdom_private);
					out.close();
				}
			}
		}
		return r;
	}

	bool status_confirm_or_delete(const std::string& path_private_db, CRYPTO_FILE_TYPE t, bool& key_updated, bool verbose=false)
	{
		bool r = true;
		key_updated = false;
		uint32_t cnt_deleted 	= 0;
		uint32_t cnt_confirmed 	= 0;

        if (t == CRYPTO_FILE_TYPE::RSA_KEY_STATUS)
        {
		    std::string filePrivateRSADB = path_private_db + RSA_MY_PRIVATE_DB;
            std::string fileStatusRSADB  = path_private_db + RSA_MY_STATUS_DB;

			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_status;

			bool ok = true;
			if (cryptoAL::fileexists(fileStatusRSADB) == false)
			{
				ok = false;
			}
			else if (cryptoAL::fileexists(filePrivateRSADB) == false)
			{
				std::cerr << "WARNING no file: " << filePrivateRSADB << std:: endl;
				ok = false;
			}

			if (ok)
			{
                {
                    std::ifstream infile;
                    infile.open(filePrivateRSADB, std::ios_base::in);
                    infile >> bits(map_rsa_private);
                    infile.close();
				}

				{
                    std::ifstream infile;
                    infile.open(fileStatusRSADB, std::ios_base::in);
                    infile >> bits(map_rsa_status);
                    infile.close();
                }


				for(auto& [keyname, kstatus] : map_rsa_status)
				{
					if (map_rsa_private.find(keyname) != map_rsa_private.end())
					{
						// Extra validation if same key...

						if (kstatus.confirmed == false)
						{
							// confirming reception by recipient
							auto& mykey = map_rsa_private[keyname];
							if (mykey.confirmed == false)
							{
								key_updated 	= true;
								mykey.confirmed = true;
								mykey.dt_confirmed = cryptoAL::get_current_time_and_date();
								cnt_confirmed++;

								if (verbose)
                                {
                                    std::cout << "My RSA public key has been CONFIRMED: " << keyname << std::endl;
                                }
							}
						}
						if (kstatus.deleted == true)
						{
							// confirming deleted by recipient
							auto& mykey = map_rsa_private[keyname];
							if (mykey.deleted == true)
							{
								// delete
								key_updated = true;
								map_rsa_private.erase(keyname);
								cnt_deleted++;

								if (verbose)
                                {
                                    std::cout << "My RSA public key has been DELETED: " << keyname << std::endl;
                                }
							}
						}
					}
					else
					{
					}

				}

				if (key_updated == true)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(filePrivateRSADB + ".bck", std::ios_base::out);
						outfile << bits(map_rsa_private);
						outfile.close();
					}

					// save private
					{
                        std::ofstream out;
                        out.open(filePrivateRSADB, std::ios_base::out);
                        out << bits(map_rsa_private);
                        out.close();
					}
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::ECC_KEY_STATUS)
        {
			std::string filePrivateECCDB = path_private_db + ECCKEY_MY_PRIVATE_DB;
            std::string fileStatusECCDB  = path_private_db + ECC_MY_STATUS_DB;

			std::map< std::string, ecc_key > map_ecc_private;
			std::map< std::string, ecc_key > map_ecc_status;

			bool ok = true;
			if (cryptoAL::fileexists(fileStatusECCDB) == false)
			{
				ok = false;
			}
			else if (cryptoAL::fileexists(filePrivateECCDB) == false)
			{
				std::cerr << "WARNING no file: " << filePrivateECCDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
                {
                    std::ifstream infile;
                    infile.open(filePrivateECCDB, std::ios_base::in);
                    infile >> bits(map_ecc_private);
                    infile.close();
                }

				{
                    std::ifstream infile;
                    infile.open(fileStatusECCDB, std::ios_base::in);
                    infile >> bits(map_ecc_status);
                    infile.close();
				}

				for(auto& [keyname, kstatus] : map_ecc_status)
				{
					if (map_ecc_private.find(keyname) != map_ecc_private.end())
					{
						// Extra validation if same key...

						if (kstatus.confirmed == false)
						{
							// confirming reception by recipient
							auto& mykey = map_ecc_private[keyname];
							if (mykey.confirmed == false)
							{
								key_updated 	= true;
								mykey.confirmed = true;
								mykey.dt_confirmed = cryptoAL::get_current_time_and_date();
								cnt_confirmed++;

								if (verbose)
                                {
                                    std::cout << "My ECC public key has been CONFIRMED: " << keyname << std::endl;
                                }
							}
						}
						if (kstatus.deleted == true)
						{
							// confirming deleted by recipient
							auto& mykey = map_ecc_private[keyname];
							if (mykey.deleted == true)
							{
								// delete
								key_updated = true;
								map_ecc_private.erase(keyname);
								cnt_deleted++;

								if (verbose)
                                {
                                    std::cout << "My ECC public key has been DELETED: " << keyname << std::endl;
                                }
							}
						}
					}
                }

				if (key_updated == true)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(filePrivateECCDB + ".bck", std::ios_base::out);
						outfile << bits(map_ecc_private);
						outfile.close();
					}

					// save private
					{
						std::ofstream out;
						out.open(filePrivateECCDB, std::ios_base::out);
						out << bits(map_ecc_private);
						out.close();
					}
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::ECC_DOM_STATUS)
        {
			std::string filePrivateECCDB = path_private_db + ECC_DOMAIN_DB;
            std::string fileStatusECCDB  = path_private_db + ECCDOM_MY_STATUS_DB;

			std::map< std::string, ecc_domain > map_ecc_private;
			std::map< std::string, ecc_domain > map_ecc_status;

			bool ok = true;
			if (cryptoAL::fileexists(fileStatusECCDB) == false)
			{
				ok = false;
			}
			else if (cryptoAL::fileexists(filePrivateECCDB) == false)
			{
				std::cerr << "WARNING no file: " << filePrivateECCDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
                {
                    std::ifstream infile;
                    infile.open(filePrivateECCDB, std::ios_base::in);
                    infile >> bits(map_ecc_private);
                    infile.close();
                }

				{
                    std::ifstream infile;
                    infile.open(fileStatusECCDB, std::ios_base::in);
                    infile >> bits(map_ecc_status);
                    infile.close();
				}

				for(auto& [keyname, kstatus] : map_ecc_status)
				{
					if (map_ecc_private.find(keyname) != map_ecc_private.end())
					{
						// Extra validation if same key...

						if (kstatus.confirmed == false)
						{
							// confirming reception by recipient
							auto& mykey = map_ecc_private[keyname];
							if (mykey.confirmed == false)
							{
								key_updated 	= true;
								mykey.confirmed = true;
								mykey.dt_confirmed = cryptoAL::get_current_time_and_date();
								cnt_confirmed++;

								if (verbose)
                                {
                                    std::cout << "My ECC DOMAIN key has been CONFIRMED: " << keyname << std::endl;
                                }
							}
						}
						if (kstatus.deleted == true)
						{
							// confirming deleted by recipient
							auto& mykey = map_ecc_private[keyname];
							if (mykey.deleted == true)
							{
								// delete
								key_updated = true;
								map_ecc_private.erase(keyname);
								cnt_deleted++;

								if (verbose)
                                {
                                    std::cout << "My ECC DOMAIN key has been DELETED: " << keyname << std::endl;
                                }
							}
						}
					}
                }

				if (key_updated == true)
				{
					// backup
					{
						std::ofstream outfile;
						outfile.open(filePrivateECCDB + ".bck", std::ios_base::out);
						outfile << bits(map_ecc_private);
						outfile.close();
					}

					// save private
					{
						std::ofstream out;
						out.open(filePrivateECCDB, std::ios_base::out);
						out << bits(map_ecc_private);
						out.close();
					}
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::HH_KEY_STATUS)
        {
			//...
		}

		if (verbose)
		{
			if (cnt_confirmed > 0) 	std::cout << "Number of public keys CONFIRMED: " << cnt_confirmed << std::endl;
			if (cnt_deleted > 0)	std::cout << "Number of public keys DELETED:   " << cnt_deleted << std::endl;
		}

		return r;
	}

	// my ((k.confirmed == false) || (k.deleted == true)) - resending until confirmed
	bool export_public_status_key(const std::string& path_public_db, CRYPTO_FILE_TYPE t, bool& key_exist, bool verbose=false)
    {
        bool r 		= true;
		key_exist 	= false;
		uint32_t cnt = 0;

		if (t == CRYPTO_FILE_TYPE::RSA_KEY_STATUS)
        {
            std::string filePublicDB = path_public_db + RSA_OTHER_PUBLIC_DB;
            std::string fileStatusDB = path_public_db + RSA_OTHER_STATUS_DB;

			std::map< std::string, generate_rsa::rsa_key > map_rsa_public;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_status;

			bool ok = true;
			if (cryptoAL::fileexists(filePublicDB) == false)
			{
				//std::cerr << "WARNING no file: " << filePublicDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
				std::ifstream infile;
				infile.open(filePublicDB, std::ios_base::in);
				infile >> bits(map_rsa_public);
				infile.close();

				for(auto& [keyname, k] : map_rsa_public)
				{
					if ((k.confirmed == false) || (k.deleted == true))
					{
						key_exist = true;
						cnt++;

						generate_rsa::rsa_key key_public;

						key_public.key_size_in_bits = k.key_size_in_bits ;
						key_public.s_n = k.s_n ;
						key_public.s_e = k.s_e ;
						key_public.s_d = "";

						key_public.confirmed = k.confirmed;
						key_public.deleted = k.deleted;
						key_public.usage_count = k.usage_count;
						key_public.dt_confirmed = k.dt_confirmed;

                   		map_rsa_status.insert(std::make_pair(keyname,  key_public));

						if (verbose)
						{
							if (k.confirmed == false)
								std::cout << "My RSA public key with status [confirmed == false] will be EXPORTED: " << keyname << std::endl;
							else if (k.deleted == true)
								std::cout << "My RSA public key with status [deleted == true] will be EXPORTED: " << keyname << std::endl;
						}
					}
				}

				if (key_exist == true)
				{
					std::ofstream out;
					out.open(fileStatusDB, std::ios_base::out);
					out << bits(map_rsa_status);
					out.close();
				}
			}
        }
        else if (t == CRYPTO_FILE_TYPE::ECC_KEY_STATUS)
        {
			std::string filePublicDB = path_public_db + ECCKEY_OTHER_PUBLIC_DB;
            std::string fileStatusDB = path_public_db + ECC_OTHER_STATUS_DB;

			std::map< std::string, ecc_key > map_ecc_public;
			std::map< std::string, ecc_key > map_ecc_status;

			bool ok = true;
			if (cryptoAL::fileexists(filePublicDB) == false)
			{
				//std::cerr << "WARNING no file: " << filePublicDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
				std::ifstream infile;
				infile.open(filePublicDB, std::ios_base::in);
				infile >> bits(map_ecc_public);
				infile.close();

				for(auto& [keyname, k] : map_ecc_public)
				{
					if ((k.confirmed == false) || (k.deleted == true))
					{
						cnt++;
						key_exist = true;
						ecc_key key_public(k.dom, k.s_kg_x, k.s_kg_y, "");

						key_public.confirmed 	= k.confirmed;
						key_public.deleted 		= k.deleted;
						key_public.usage_count 	= k.usage_count;
						key_public.dt_confirmed = k.dt_confirmed;

                   		map_ecc_status.insert(std::make_pair(keyname,  key_public));

						if (verbose)
						{
							if (k.confirmed == false)
								std::cout << "My ECC public key with status [confirmed == false] will be EXPORTED: " << keyname << std::endl;
							else if (k.deleted == true)
								std::cout << "My ECC public key with status [deleted == true] will be EXPORTED: " << keyname << std::endl;
						}
					}
				}

				if (key_exist == true)
				{
					std::ofstream out;
					out.open(fileStatusDB, std::ios_base::out);
					out << bits(map_ecc_status);
					out.close();
				}
			}
        }
		else if (t == CRYPTO_FILE_TYPE::ECC_DOM_STATUS)
        {
			std::string filePublicDB = path_public_db + ECC_DOMAIN_OTHER_DB;
            std::string fileStatusDB = path_public_db + ECCDOM_OTHER_STATUS_DB;

			std::map< std::string, ecc_domain > map_ecc_public;
			std::map< std::string, ecc_domain > map_ecc_status;

			bool ok = true;
			if (cryptoAL::fileexists(filePublicDB) == false)
			{
				//std::cerr << "WARNING no file: " << filePublicDB << std:: endl;
				ok = false;
			}

			if (ok)
			{
				std::ifstream infile;
				infile.open(filePublicDB, std::ios_base::in);
				infile >> bits(map_ecc_public);
				infile.close();

				for(auto& [keyname, k] : map_ecc_public)
				{
					if ((k.confirmed == false) || (k.deleted == true))
					{
						cnt++;
						key_exist = true;
						ecc_domain key_public;
						key_public.create_from(k);

						key_public.confirmed 	= k.confirmed;
						key_public.deleted 		= k.deleted;
						key_public.usage_count 	= k.usage_count;
						key_public.dt_confirmed = k.dt_confirmed;

                   		map_ecc_status.insert(std::make_pair(keyname,  key_public));

						if (verbose)
						{
							if (k.confirmed == false)
								std::cout << "The other ECC DOMAIN key with status [confirmed == false] will be EXPORTED: " << keyname << std::endl;
							else if (k.deleted == true)
								std::cout << "The other ECC DOMAIN key with status [deleted == true] will be EXPORTED: " << keyname << std::endl;
						}
					}
				}

				if (key_exist == true)
				{
					std::ofstream out;
					out.open(fileStatusDB, std::ios_base::out);
					out << bits(map_ecc_status);
					out.close();
				}
			}
        }
        else if (t == CRYPTO_FILE_TYPE::HH_KEY_STATUS)
        {
			//...
        }

        return r;
	}

	// FULL copy of my public keys send to recipient (on encoding) - not incremental...TODO
	// We maintain a quota of maximum keys, creating new ones and deleting confirmed old ones
    bool export_public_key(const std::string& path_private_db, CRYPTO_FILE_TYPE t, bool& key_exist, bool verbose=false)
    {
        bool r = true;
		key_exist = false;
		uint32_t cnt = 0;

        if (t == CRYPTO_FILE_TYPE::RSA_PUBLIC)
        {
            std::string filePrivateRSADB = path_private_db + RSA_MY_PRIVATE_DB;
            std::string filePublicRSADB  = path_private_db + RSA_MY_PUBLIC_DB;

			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_public;

			if (cryptoAL::fileexists(filePrivateRSADB) == true)
			{
				std::ifstream infile;
				infile.open(filePrivateRSADB, std::ios_base::in);
				infile >> bits(map_rsa_private);
				infile.close();

				for(auto& [keyname, k] : map_rsa_private)
				{
					//if (k.deleted == false)
					{
						cnt++;
						key_exist = true;
						generate_rsa::rsa_key key_public;

						key_public.key_size_in_bits = k.key_size_in_bits ;
						key_public.s_n = k.s_n ;
						key_public.s_e = k.s_e ;
						key_public.s_d = "" ;

						key_public.confirmed    = k.confirmed;
						key_public.deleted      = k.deleted;
						key_public.usage_count  = k.usage_count;
						key_public.dt_confirmed = k.dt_confirmed;

						map_rsa_public.insert(std::make_pair(keyname,  key_public));
					}
				}

				if (key_exist == true)
				{
					std::ofstream out;
					out.open(filePublicRSADB, std::ios_base::out);
					out << bits(map_rsa_public);
					out.close();
				}

				if (verbose)
				{
					std::cout << "Number of RSA public keys to export: " << cnt << std::endl;
				}
			}
			else
			{
			  	//std::cerr << "WARNING no file: " << filePrivateRSADB << std:: endl;
			}
        }
        else if (t == CRYPTO_FILE_TYPE::ECC_PUBLIC)
        {
			std::string filePrivateECCDB = path_private_db + ECCKEY_MY_PRIVATE_DB;
            std::string filePublicECCDB  = path_private_db + ECCKEY_MY_PUBLIC_DB;

			std::map< std::string, ecc_key > map_ecc_private;
			std::map< std::string, ecc_key > map_ecc_public;

			if (cryptoAL::fileexists(filePrivateECCDB) == true)
			{
				std::ifstream infile;
				infile.open (filePrivateECCDB, std::ios_base::in);
				infile >> bits(map_ecc_private);
				infile.close();

				for(auto& [keyname, k] : map_ecc_private)
				{
					//if (k.deleted == false)
					{
						cnt++;
						key_exist = true;
						ecc_key key_public(k.dom, k.s_kg_x, k.s_kg_y, "");

						key_public.confirmed    = k.confirmed;
						key_public.deleted      = k.deleted;
						key_public.usage_count  = k.usage_count;
						key_public.dt_confirmed = k.dt_confirmed;

						map_ecc_public.insert(std::make_pair(keyname,  key_public) );
					}
				}

				if (key_exist == true)
				{
					std::ofstream out;
					out.open(filePublicECCDB, std::ios_base::out);
					out << bits(map_ecc_public);
					out.close();
				}

				if (verbose)
				{
					std::cout << "Number of ECC public keys to export: " << cnt << std::endl;
				}
			}
			else
			{
			  	//std::cerr << "WARNING no file: " << filePrivateECCDB << std:: endl;
			}
        }
		else if (t == CRYPTO_FILE_TYPE::ECC_DOMAIN)
        {
			std::string fileMyDomainDB 			= path_private_db + ECC_DOMAIN_DB;
            std::string fileMyPublicDomainDB  	= path_private_db + ECC_DOMAIN_PUBLIC_DB;

			std::map< std::string, ecc_domain > map_my_eccdomain;
			std::map< std::string, ecc_domain > map_public_eccdomain;

			if (cryptoAL::fileexists(fileMyDomainDB) == true)
			{
				std::ifstream infile;
				infile.open (fileMyDomainDB, std::ios_base::in);
				infile >> bits(map_public_eccdomain);
				infile.close();

				for(auto& [keyname, k] : map_public_eccdomain)
				{
					//if (k.deleted == false)
					{
						cnt++;
						key_exist = true;
						ecc_domain key_public;
						key_public.create_from(k);

						key_public.confirmed    = k.confirmed;
						key_public.deleted      = k.deleted;
						key_public.usage_count  = k.usage_count;
						key_public.dt_confirmed = k.dt_confirmed;

						map_public_eccdomain.insert(std::make_pair(keyname,  key_public) );
					}
				}

				if (key_exist == true)
				{
					std::ofstream out;
					out.open(fileMyPublicDomainDB, std::ios_base::out);
					out << bits(map_public_eccdomain);
					out.close();
				}

				if (verbose)
				{
					std::cout << "Number of ECC DOMAIN keys to export: " << cnt << std::endl;
				}
			}
			else
			{
			  	//std::cerr << "WARNING no file: " << fileMyDomainDB << std:: endl;
			}
        }
        else if (t == CRYPTO_FILE_TYPE::HH_PUBLIC)
        {
            std::string filePrivateHistoDB = path_private_db + HHKEY_MY_PRIVATE_DECODE_DB;
            std::string filePublicHistoDB  = path_private_db + HHKEY_MY_PUBLIC_DECODE_DB;

			if (cryptoAL::fileexists(filePrivateHistoDB) == true)
			{
                std::map<uint32_t, history_key> map_histo;
                std::map<std::string, history_key_public> map_histo_pub;

                std::ifstream infile;
                infile.open (filePrivateHistoDB, std::ios_base::in);
                infile >> bits(map_histo);
                infile.close();

                for(auto& [seqkey, k] : map_histo)
                {
					//if (k.deleted == false)
					{
						cnt++;
						key_exist = true;

						history_key_public kout;
						history_key_to_public(k, kout); // kout = SHA (kin.data_sha[0]+kin.data_sha[1]+kin.data_sha[2]);

						map_histo_pub[k.data_sha[0]] = kout;
					}
                }

				if (key_exist == true)
				{
					std::ofstream outstream;
					outstream.open(filePublicHistoDB, std::ios_base::out);
					outstream << bits(map_histo_pub);
					outstream.close();
				}

				if (verbose)
				{
					std::cout << "Number of HH public keys to export: " << cnt << std::endl;
				}
			}
			else
			{
				//std::cerr << "WARNING no file: " << filePrivateHistoDB << std:: endl;
			}
        }
        return r;
    }

	bool export_public_keys(std::vector<public_key_desc_exporting>& vout,
                            const std::string&  folder_my_private_rsa,
                            const std::string&  folder_my_private_ecc,
                            const std::string&  folder_my_private_hh,
                            bool verbose = false)
	{
		bool key_exist[4] = {false};
        bool r = true;

		if (verbose) std::cout << "-------------------------------------- "<< std::endl;
		if (verbose) std::cout << "Exporting public keys: "<< std::endl;
		if (verbose) std::cout << "-------------------------------------- "<< std::endl;

        if (r) r = export_public_key(folder_my_private_rsa  , CRYPTO_FILE_TYPE::RSA_PUBLIC, key_exist[0], verbose);
        if (r) r = export_public_key(folder_my_private_ecc  , CRYPTO_FILE_TYPE::ECC_PUBLIC, key_exist[1], verbose);
		if (r) r = export_public_key(folder_my_private_ecc  , CRYPTO_FILE_TYPE::ECC_DOMAIN, key_exist[2], verbose);
        if (r) r = export_public_key(folder_my_private_hh   , CRYPTO_FILE_TYPE::HH_PUBLIC,  key_exist[3], verbose);

        if (r)
        {
            if (key_exist[0]) vout.emplace_back(folder_my_private_rsa  , CRYPTO_FILE_TYPE::RSA_PUBLIC);
            if (key_exist[1]) vout.emplace_back(folder_my_private_ecc  , CRYPTO_FILE_TYPE::ECC_PUBLIC);
			if (key_exist[2]) vout.emplace_back(folder_my_private_ecc  , CRYPTO_FILE_TYPE::ECC_DOMAIN);
            if (key_exist[3]) vout.emplace_back(folder_my_private_hh   , CRYPTO_FILE_TYPE::HH_PUBLIC);
        }
		if (verbose) std::cout << "-------------------------------------- " << std::endl << std::endl;
        return r;
	}

	bool export_public_status_keys(	std::vector<status_key_desc_exporting>& vout,
									const std::string&  folder_other_public_rsa,
									const std::string&  folder_other_public_ecc,
									const std::string&  folder_other_public_hh,
									bool verbose = false)
	{
		bool key_exist[4] = {false};
        bool r = true;
		if (verbose) std::cout << "-------------------------------------- "<< std::endl;
		if (verbose) std::cout << "Exporting other status keys: "<< std::endl;
		if (verbose) std::cout << "-------------------------------------- "<< std::endl;

        if (r) r = export_public_status_key(folder_other_public_rsa  , CRYPTO_FILE_TYPE::RSA_KEY_STATUS, key_exist[0], verbose);
        if (r) r = export_public_status_key(folder_other_public_ecc  , CRYPTO_FILE_TYPE::ECC_KEY_STATUS, key_exist[1], verbose);
		if (r) r = export_public_status_key(folder_other_public_ecc  , CRYPTO_FILE_TYPE::ECC_DOM_STATUS, key_exist[2], verbose);
        if (r) r = export_public_status_key(folder_other_public_hh   , CRYPTO_FILE_TYPE::HH_KEY_STATUS,  key_exist[3], verbose);

        if (r)
        {
            if (key_exist[0]) vout.emplace_back(folder_other_public_rsa  , CRYPTO_FILE_TYPE::RSA_KEY_STATUS);
            if (key_exist[1]) vout.emplace_back(folder_other_public_ecc  , CRYPTO_FILE_TYPE::ECC_KEY_STATUS);
			if (key_exist[2]) vout.emplace_back(folder_other_public_ecc  , CRYPTO_FILE_TYPE::ECC_DOM_STATUS);
            if (key_exist[3]) vout.emplace_back(folder_other_public_hh   , CRYPTO_FILE_TYPE::HH_KEY_STATUS);
        }
		if (verbose) std::cout << "-------------------------------------- "<< std::endl<< std::endl;
        return r;
	}

	bool sortkey(const std::string& a, const std::string& b)
	{
		int na = (int)a.size() - 19; if (na < 1) na = 0;
		int nb = (int)b.size() - 19; if (nb < 1) nb = 0;
		std::string ta = a.substr(na);
		std::string tb = b.substr(nb);
		return (ta<tb);
	}

	// With ECC keys we can generate new r,rG keys when encoding with recipient r'G public key
	bool get_n_keys(    keyspec_type t, uint32_t n, bool first, bool last, bool random, bool newkeys,
                        std::vector<std::string>&  vkeys_out,
						const std::string& folder_other_public_rsa,
                       	const std::string& folder_other_public_ecc,
                       	const std::string& folder_my_private_hh,
						const std::string& folder_my_private_ecc,
						bool verbose = false)
	{
        verbose=verbose;
		std::vector<std::string> vmapkeyname;

		std::map<std::string, generate_rsa::rsa_key> map_rsa_public;
		std::map<std::string, ecc_key> map_ecc_public;
		std::map<std::string, history_key_public> map_hh_public;

		if (t == keyspec_type::RSA)
		{
			//std::cout << "get_n_keys RSA in " << folder_other_public_rsa + RSA_OTHER_PUBLIC_DB << std::endl;
			std::string filePublicOtherDB = folder_other_public_rsa + RSA_OTHER_PUBLIC_DB;
			if (cryptoAL::fileexists(filePublicOtherDB) == true)
			{
				std::ifstream infile;
				infile.open (filePublicOtherDB, std::ios_base::in);
				infile >> bits(map_rsa_public);
				infile.close();

				for(auto& [keyname, k] : map_rsa_public)
				{
					vmapkeyname.push_back(keyname);
				}
			}
		}
		else if (t == keyspec_type::ECC)
		{
			//std::cout << "get_n_keys ECC in " << folder_other_public_ecc + ECCKEY_OTHER_PUBLIC_DB << std::endl;
			std::string filePublicOtherDB = folder_other_public_ecc + ECCKEY_OTHER_PUBLIC_DB;
			if (cryptoAL::fileexists(filePublicOtherDB) == true)
			{
				std::ifstream infile;
				infile.open (filePublicOtherDB, std::ios_base::in);
				infile >> bits(map_ecc_public);
				infile.close();

				for(auto& [keyname, k] : map_ecc_public)
				{
					vmapkeyname.push_back(keyname);
				}
			}
		}
		else if (t == keyspec_type::HH)
		{
			//std::cout << "get_n_keys HH in " << folder_my_private_hh + HHKEY_MY_PRIVATE_ENCODE_DB << std::endl;
			std::string fileMyPrivaterDB = folder_my_private_hh + HHKEY_MY_PRIVATE_ENCODE_DB;
			if (cryptoAL::fileexists(fileMyPrivaterDB) == true)
			{
				std::ifstream infile;
				infile.open (fileMyPrivaterDB, std::ios_base::in);
				infile >> bits(map_hh_public);
				infile.close();

				for(auto& [keyname, k] : map_hh_public)
				{
					vmapkeyname.push_back(keyname);
				}
			}
		}

		// sort with date in key name MY_RSAKEY_512_2023-03-18_23:32:34
		if (vmapkeyname.size() > 0)
		{
			std::sort(vmapkeyname.begin(), vmapkeyname.end(), sortkey);

			if (first)
			{
				if (n > (uint32_t)vmapkeyname.size()) n = (uint32_t)vmapkeyname.size();
				for(uint32_t i = 0; i< n; i++)
				{
					if (i < (uint32_t)vmapkeyname.size())
						vkeys_out.push_back(vmapkeyname[i]);
					else
						{std::cerr << "error " << i << std::endl; return false;}
				}
			}
			else if (last)
			{
                size_t cnt=0;
				if (n > vmapkeyname.size()) n = (uint32_t)vmapkeyname.size();
				for(long long i = (long long)vmapkeyname.size() - 1; i >= 0; i--)
				{
                    if (cnt < n)
                    {
                        if (i < (long long)vmapkeyname.size())
						{
							cnt++;
                            vkeys_out.push_back(vmapkeyname[i]);
						}
                        else
                        {
                            std::cerr << "internal error " << i << std::endl;
                            return false;
                        }
                    }
                    else
                    {
                        break;
                    }
				}
			}
			else if (random)
			{
				random_engine rd;

				for(long long i = 0; i< (long long)n; i++)
				{
					long long t = (long long) (rd.get_rand() * vmapkeyname.size());
					if ( (t>=0) && (t < (long long)vmapkeyname.size()) )
					{
						vkeys_out.push_back(vmapkeyname[t]);
					}
					else
                    {
                        std::cerr << "internal error " << i << std::endl;
                        return false;
                    }
				}
			}
			/*
			else if (newkeys)
			{
				// count key usage
				uint32_t cnt_usage_zero = 0;
				for(auto& [kname, key] : map_ecc_public)
				{
                    if (key,usage_count == 0)
                        cnt_usage_zero++;
				}
				if (cnt_usage_zero < n)
				{
					// generate new ECC keys;
					// compute vmapkeyname with cnt_usage == 0
					// .....
				}
			}
			*/
		}
		return true;
	}

	bool materialize_keys(	keyspec& key_in,
							const std::string& folder_other_public_rsa,
                            const std::string& folder_other_public_ecc,
                            const std::string& folder_my_private_hh,
							const std::string& folder_my_private_ecc,
							bool verbose = false)
	{
		bool r = true;

		if (key_in.is_spec)
		{
			if (key_in.first_n > 0)
			{
				r = get_n_keys(key_in.ktype, key_in.first_n, true, false, false, false, key_in.vmaterialized_keyname,
				folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,verbose);
			}
			if (key_in.last_n > 0)
			{
				r = get_n_keys(key_in.ktype, key_in.last_n, false, true, false, false, key_in.vmaterialized_keyname,
				folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,verbose);
			}
			if (key_in.random_n > 0)
			{
				r = get_n_keys(key_in.ktype, key_in.random_n, false, false, true, false, key_in.vmaterialized_keyname,
				folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,verbose);
			}
			if (key_in.new_n > 0)
			{
				r = get_n_keys(key_in.ktype, key_in.random_n, false, false, false, true, key_in.vmaterialized_keyname,
				folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,verbose);
			}
		}
		return r;
	}

}
}
#endif
