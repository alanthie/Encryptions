#ifndef CRYPTO_KEYMGR_H_INCLUDED
#define CRYPTO_KEYMGR_H_INCLUDED

#include "crypto_const.hpp"
#include "crypto_ecckey.hpp"
#include "qa/rsa_gen.hpp"
#include "crypto_history.hpp"
#include "data.hpp"
#include "crypto_key_parser.hpp"
#include "random_engine.hpp"
#include "crc32a.hpp"
#include "c_plus_plus_serializer.h"
#include "crypto_dbmgr.hpp"

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

	// OTHER_PUBLIC_DB have been marked for delete
	bool delete_public_keys_marked_for_deleting(const std::string& path_public_db, CRYPTO_FILE_TYPE t, bool& key_deleted, bool verbose=false)
	{
		bool r = true;
		key_deleted = false;
		verbose=verbose;

		if (t == CRYPTO_FILE_TYPE::RSA_PUBLIC)
        {
		    std::string fileDB = path_public_db + RSA_OTHER_PUBLIC_DB;
			std::map< std::string, cryptoAL::rsa::rsa_key > map_rsa_public;

			bool ok = true;
			if (file_util::fileexists(fileDB) == false)
			{
				if (verbose) std::cerr << "WARNING no file: " << fileDB << std:: endl;
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

				std::vector<std::string> v;
				for(auto& [keyname, k] : map_rsa_public)
				{
					if (k.deleted == true)
					{
						// delete
						key_deleted = true;
						v.push_back(keyname);
					}
				}
				for (size_t i=0;i<v.size();i++)
				{
					map_rsa_public.erase(v[i]);
					//std::cout << "other public rsa key deleted: " << v[i] << std::endl;
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

					// save
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
			std::map<std::string, ecc_key> map_ecc_public;

			bool ok = true;
			if (file_util::fileexists(fileDB) == false)
			{
				if (verbose)std::cerr << "WARNING no file: " << fileDB << std:: endl;
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

				std::vector<std::string> v;
				for(auto& [keyname, k] : map_ecc_public)
				{
					if (k.deleted == true)
					{
						// delete
						key_deleted = true;
						v.push_back(keyname);
					}
				}
				for (size_t i=0;i<v.size();i++)
				{
					map_ecc_public.erase(v[i]);
					//std::cout << "other public ecc key deleted: " << v[i] << std::endl;
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

					// save
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
			std::map<std::string, history_key_public> map_hh_public;

			bool ok = true;
			if (file_util::fileexists(fileDB) == false)
			{
				if (verbose) std::cerr << "WARNING no file: " << fileDB << std:: endl;
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

				std::vector<std::string> v;
				for(auto& [keyname, k] : map_hh_public)
				{
					if (k.deleted == true)
					{
						// delete
						key_deleted = true;
						v.push_back(keyname);

					}
				}

				for (size_t i=0;i<v.size();i++)
				{
					map_hh_public.erase(v[i]);
					//std::cout << "other public hh key deleted: " << v[i] << std::endl;
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

					// save
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

	bool merge_other_ecc_domain(const std::string& path_ecc_private_db, const std::string& path_ecc_other_db, bool& key_merged, [[maybe_unused]] bool verbose=false)
	{
		bool r = true;

		std::string filePrivateECCDB = path_ecc_private_db  + ECC_DOMAIN_DB;
  		std::string fileStatusECCDB  = path_ecc_other_db    + ECC_DOMAIN_OTHER_DB;

		std::map< std::string, ecc_domain > map_eccdom_private;
		std::map< std::string, ecc_domain > map_eccdom_other;

		bool ok = true;
		if (file_util::fileexists(fileStatusECCDB) == false)
		{
			ok = false;
		}
		else if (file_util::fileexists(filePrivateECCDB) == false)
		{
			// ok will create one...
		}

		if (ok)
		{
			if (file_util::fileexists(filePrivateECCDB) == true)
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
							key_public.dt_confirmed = cryptoAL::parsing::get_current_time_and_date();

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
				if (file_util::fileexists(filePrivateECCDB) == true)
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

	bool status_confirm_or_delete(cryptoAL::db::db_mgr& dbmgr, const std::string& path_private_db, CRYPTO_FILE_TYPE t, bool& key_updated, [[maybe_unused]] bool verbose=false)
	{
		bool r = true;
		key_updated = false;
		uint32_t cnt_deleted 	= 0;
		uint32_t cnt_confirmed 	= 0;

        if (t == CRYPTO_FILE_TYPE::RSA_KEY_STATUS)
        {
		    std::string filePrivateRSADB = path_private_db + RSA_MY_PRIVATE_DB;
            std::string fileStatusRSADB  = path_private_db + RSA_MY_STATUS_DB;

			std::map< std::string, cryptoAL::rsa::rsa_key > map_rsa_status;

			bool ok = true;
			if (file_util::fileexists(fileStatusRSADB) == false)
			{
				ok = false;
			}
			else if (file_util::fileexists(filePrivateRSADB) == false)
			{
				if (verbose) std::cerr << "WARNING no file: " << filePrivateRSADB << std:: endl;
				ok = false;
			}


			std::map<std::string, cryptoAL::rsa::rsa_key>* pmap_rsa = nullptr;
			r = dbmgr.get_rsa_map(filePrivateRSADB, &pmap_rsa, false);
			if (r == false)
			{
				std::cout << "dbmgr.get_rsa_map() == false" << std:: endl;
				return false;
			}
			if (pmap_rsa == nullptr)
			{
				std::cout << "pmap_rsa == nullptr" << std:: endl;
				return false;
			}

			std::map<std::string, cryptoAL::rsa::rsa_key>& map_rsa_private = *pmap_rsa;
			if (ok)
			{
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
								mykey.dt_confirmed = cryptoAL::parsing::get_current_time_and_date();
								cnt_confirmed++;

								if (verbose)
                                {
                                    std::cout << "My RSA key has been CONFIRMED: " << keyname << std::endl;
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

								cryptoAL::db::transaction t;
								{
									t.key_type = "rsa";
									t.key_name = keyname;
									t.decoder_erase_key = true;
									t.decoder_add_usage_count = false;
								}
								dbmgr.add_trans(t);

								if (verbose)
                                {
                                    std::cout << "My RSA key has been DELETED: " << keyname << std::endl;
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
					dbmgr.mark_rsa_as_changed(filePrivateRSADB);
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::ECC_KEY_STATUS)
        {
			std::string filePrivateECCDB = path_private_db + ECCKEY_MY_PRIVATE_DB;
            std::string fileStatusECCDB  = path_private_db + ECC_MY_STATUS_DB;

			std::map< std::string, ecc_key > map_ecc_status;

			bool ok = true;
			if (file_util::fileexists(fileStatusECCDB) == false)
			{
				ok = false;
			}
			else if (file_util::fileexists(filePrivateECCDB) == false)
			{
				if (verbose) std::cerr << "WARNING no file: " << filePrivateECCDB << std:: endl;
				ok = false;
			}

			std::map<std::string, cryptoAL::ecc_key>* pmap_ecc = nullptr;
			r = dbmgr.get_ecckey_map(filePrivateECCDB, &pmap_ecc, false);
			if (r == false)
			{
				std::cout << "dbmgr.get_ecckey_map() == false" << std:: endl;
				return false;
			}
			if (pmap_ecc == nullptr)
			{
				std::cout << "pmap_ecc == nullptr" << std:: endl;
				return false;
			}
			std::map<std::string, ecc_key>& map_ecc_private = *pmap_ecc;

			if (ok)
			{
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
								mykey.dt_confirmed = cryptoAL::parsing::get_current_time_and_date();
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

								cryptoAL::db::transaction t;
								{
									t.key_type = "ecc";
									t.key_name = keyname;
									t.decoder_erase_key = true;
									t.decoder_add_usage_count = false;
								}
								dbmgr.add_trans(t);

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
					dbmgr.mark_ecckey_as_changed(filePrivateECCDB);
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::ECC_DOM_STATUS)
        {
			std::string filePrivateECCDB = path_private_db + ECC_DOMAIN_DB;
            std::string fileStatusECCDB  = path_private_db + ECCDOM_MY_STATUS_DB;

			std::map<std::string, ecc_domain> map_ecc_status;

			bool ok = true;
			if (file_util::fileexists(fileStatusECCDB) == false)
			{
				ok = false;
			}
			else if (file_util::fileexists(filePrivateECCDB) == false)
			{
				if (verbose) std::cerr << "WARNING no file: " << filePrivateECCDB << std:: endl;
				ok = false;
			}

			std::map<std::string, cryptoAL::ecc_domain>* pmap_eccdom = nullptr;
			r = dbmgr.get_eccdomain_map(filePrivateECCDB, &pmap_eccdom, false);
			if (r == false)
			{
				std::cout << "dbmgr.get_eccdomain_map() == false" << std:: endl;
				return false;
			}
			if (pmap_eccdom == nullptr)
			{
				std::cout << "pmap_eccdom == nullptr" << std:: endl;
				return false;
			}
			std::map<std::string, ecc_domain>&  map_ecc_private = *pmap_eccdom;

			if (ok)
			{
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
								mykey.dt_confirmed = cryptoAL::parsing::get_current_time_and_date();
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

								cryptoAL::db::transaction t;
								{
									t.key_type = "eccdom";
									t.key_name = keyname;
									t.decoder_erase_key = true;
									t.decoder_add_usage_count = false;
								}
								dbmgr.add_trans(t);

								if (VERBOSE_DEBUG)
                                {
                                    std::cout << "My ECC DOMAIN key has been DELETED: " << keyname << std::endl;
                                }
							}
						}
					}
                }

				if (key_updated == true)
				{
					dbmgr.mark_eccdom_as_changed(filePrivateECCDB);
				}
			}
		}
		else if (t == CRYPTO_FILE_TYPE::HH_KEY_STATUS)
        {
			//...
		}

		if (VERBOSE_DEBUG)
		{
			if (cnt_confirmed > 0) 	std::cout << "Number of public keys CONFIRMED: " << cnt_confirmed << std::endl;
			if (cnt_deleted > 0)	std::cout << "Number of public keys DELETED:   " << cnt_deleted << std::endl;
		}

		return r;
	}

	// my ((k.confirmed == false) || (k.deleted == true)) - resending until confirmed
	bool export_public_status_key(const std::string& path_public_db, CRYPTO_FILE_TYPE t, bool& key_exist, [[maybe_unused]] bool verbose=false)
    {
        bool r 		= true;
		key_exist 	= false;
		uint32_t cnt = 0;

		if (t == CRYPTO_FILE_TYPE::RSA_KEY_STATUS)
        {
            std::string filePublicDB = path_public_db + RSA_OTHER_PUBLIC_DB;
            std::string fileStatusDB = path_public_db + RSA_OTHER_STATUS_DB;

			std::map< std::string, cryptoAL::rsa::rsa_key > map_rsa_public;
			std::map< std::string, cryptoAL::rsa::rsa_key > map_rsa_status;

			bool ok = true;
			if (file_util::fileexists(filePublicDB) == false)
			{
				if (verbose) std::cerr << "WARNING no file: " << filePublicDB << std:: endl;
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

						cryptoAL::rsa::rsa_key key_public;

						key_public.key_size_in_bits = k.key_size_in_bits ;
						key_public.s_n = k.s_n ;
						key_public.s_e = k.s_e ;
						key_public.s_d = "";

						key_public.confirmed = k.confirmed;
						key_public.deleted = k.deleted;
						key_public.usage_count = k.usage_count;
						key_public.dt_confirmed = k.dt_confirmed;

                   		map_rsa_status.insert(std::make_pair(keyname,  key_public));

						if (VERBOSE_DEBUG)
						{
							if (k.confirmed == false) 	std::cout << "My RSA public key with status [confirmed == false] will be EXPORTED: " << keyname << std::endl;
							else if (k.deleted == true) std::cout << "My RSA public key with status [deleted == true] will be EXPORTED: " << keyname << std::endl;
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
			if (file_util::fileexists(filePublicDB) == false)
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

						if (VERBOSE_DEBUG)
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
			if (file_util::fileexists(filePublicDB) == false)
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

						if (VERBOSE_DEBUG)
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
    bool export_public_key(const std::string& path_private_db, CRYPTO_FILE_TYPE t, bool& key_exist, [[maybe_unused]] bool verbose=false)
    {
        bool r = true;
		key_exist = false;
		uint32_t cnt = 0;

        if (t == CRYPTO_FILE_TYPE::RSA_PUBLIC)
        {
            std::string filePrivateRSADB = path_private_db + RSA_MY_PRIVATE_DB;
            std::string filePublicRSADB  = path_private_db + RSA_MY_PUBLIC_DB;

			std::map< std::string, cryptoAL::rsa::rsa_key > map_rsa_private;
			std::map< std::string, cryptoAL::rsa::rsa_key > map_rsa_public;

			if (file_util::fileexists(filePrivateRSADB) == true)
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
						cryptoAL::rsa::rsa_key key_public;

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

			if (file_util::fileexists(filePrivateECCDB) == true)
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

			if (file_util::fileexists(fileMyDomainDB) == true)
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

			if (file_util::fileexists(filePrivateHistoDB) == true)
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
		// variable now MY_RSA15KEY_15000_2023-04-13_19:20:37_0

		int na=0;
		if (a.size() > 19)
		{
			size_t delta = 19;
			while (a[a.size() - delta] != '_')
			{
				delta++;
				if (a.size() < delta)
					break;	
			}
			na = (int)a.size() - delta; 
			na++;
			if (na < 1) na = 0;
			if (na > a.size() - 1) na = a.size() - 1;
		}
		
		int nb=0;
		if (b.size() > 19)
		{
			size_t delta = 19;
			while (b[b.size() - delta] != '_')
			{
				delta++;
				if (b.size() < delta)
					break;	
			}
			nb = (int)b.size() - delta; 
			nb++;
			if (nb < 1) nb = 0;
			if (nb > b.size() - 1) nb = b.size() - 1;
		}
		
		std::string ta = a.substr(na);
		std::string tb = b.substr(nb);
		
		//std::cout << ta  <<  " " << tb << std::endl; 
		return (ta<tb);
	}

	// With ECC keys we can generate new r,rG keys when encoding with recipient r'G public key
	bool get_n_keys(    keyspec_type t, uint32_t n, bool first, bool last, bool random, bool newkeys,
                        std::vector<std::string>&  vkeys_out,
						const std::string& folder_other_public_rsa,
                       	const std::string& folder_other_public_ecc,
                       	const std::string& folder_my_private_hh,
						const std::string& folder_my_private_ecc,
						const std::string& folder_local,
						const std::string& wbaes_other_public_path,
						[[maybe_unused]] bool verbose = false)
	{
        verbose=verbose;
		std::vector<std::string> vmapkeyname;

		std::map<std::string, cryptoAL::rsa::rsa_key> map_rsa_public;
		std::map<std::string, ecc_key> map_ecc_public;
		std::map<uint32_t, history_key> map_histo;

		if (t == keyspec_type::RSA)
		{
			std::string filePublicOtherDB = folder_other_public_rsa + RSA_OTHER_PUBLIC_DB;
			if (file_util::fileexists(filePublicOtherDB) == true)
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
			std::string filePublicOtherDB = folder_other_public_ecc + ECCKEY_OTHER_PUBLIC_DB;
			if (file_util::fileexists(filePublicOtherDB) == true)
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
			std::string fileMyPrivaterDB = folder_my_private_hh + HHKEY_MY_PRIVATE_ENCODE_DB;
			if (file_util::fileexists(fileMyPrivaterDB) == true)
			{
				std::ifstream infile;
				infile.open (fileMyPrivaterDB, std::ios_base::in);
				infile >> bits(map_histo); 
				infile.close();

				for(auto& [seq, k] : map_histo)
				{
					if (k.confirmed == true)
						vmapkeyname.push_back(std::to_string(seq));
				}
			}
		}
		else if (t == keyspec_type::LocalFile)
		{
			std::vector<std::string> vbin = file_util::get_directory_files(folder_local, "binary.dat.", true);
			std::sort(vbin.begin(),vbin.end());
			for(size_t i = 0; i < vbin.size(); i++)
			{
				vmapkeyname.push_back(vbin[i]);
			}
		}

		else if ((t >= keyspec_type::wbaes_512) && (t <= keyspec_type::wbaes_32768))
		{
			std::string a;
			if      (t==keyspec_type::wbaes_512)   	a = "aes512";
			else if (t==keyspec_type::wbaes_1024)   a = "aes1024";
			else if (t==keyspec_type::wbaes_2048)   a = "aes2048";
			else if (t==keyspec_type::wbaes_4096)   a = "aes4096";
			else if (t==keyspec_type::wbaes_8192)   a = "aes8192";
			else if (t==keyspec_type::wbaes_16384)  a = "aes16384";
			else if (t==keyspec_type::wbaes_32768)  a = "aes32768";

			//aes16384_z_1_20230408112137_tyboxes.tbl
			std::vector<std::string> vbin = file_util::get_directory_files(wbaes_other_public_path, "_tyboxes.tbl", false);
			for(size_t i = 0; i < vbin.size(); i++)
			{
				if (vbin[i].substr(0, a.size()) == a)
				{
					std::size_t first = vbin[i].find_first_of("_");
					if (first!=std::string::npos)
					{
						std::size_t last = vbin[i].find_last_of("_");
						if (last!=std::string::npos)
						{
							std::string s = vbin[i].substr(first+1, last-first-1);
							vmapkeyname.push_back(s);
						}
					}
				}
			}
		}

		if (vmapkeyname.size() > 0)
		{
			if ((t == keyspec_type::RSA) || (t == keyspec_type::ECC)) std::sort(vmapkeyname.begin(), vmapkeyname.end(), sortkey);
			else std::sort(vmapkeyname.begin(), vmapkeyname.end());

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
							const std::string& folder_local,
							const std::string& wbaes_other_public_path,
							bool verbose = false)
	{
		bool r = true;

		if (key_in.is_spec)
		{
			if (key_in.first_n > 0)
			{
				r = get_n_keys(	key_in.ktype, key_in.first_n, true, false, false, false, key_in.vmaterialized_keyname,
								folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,folder_local,wbaes_other_public_path,verbose);
			}
			if (key_in.last_n > 0)
			{
				r = get_n_keys(	key_in.ktype, key_in.last_n, false, true, false, false, key_in.vmaterialized_keyname,
								folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,folder_local,wbaes_other_public_path,verbose);
			}
			if (key_in.random_n > 0)
			{
				r = get_n_keys(	key_in.ktype, key_in.random_n, false, false, true, false, key_in.vmaterialized_keyname,
								folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,folder_local,wbaes_other_public_path,verbose);
			}
			if (key_in.new_n > 0)
			{
				r = get_n_keys(	key_in.ktype, key_in.random_n, false, false, false, true, key_in.vmaterialized_keyname,
								folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh, folder_my_private_ecc,folder_local,wbaes_other_public_path,verbose);
			}
		}
		return r;
	}

}
}
#endif
