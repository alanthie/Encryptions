#ifndef PRIVATE_DB_MGR_H_INCLUDED
#define PRIVATE_DB_MGR_H_INCLUDED

#include "crypto_const.hpp"
#include "crypto_ecckey.hpp"
#include "qa/rsa_gen.hpp"
#include "crypto_history.hpp"
#include "crypto_key_parser.hpp"
#include "random_engine.hpp"
#include "data.hpp"
#include "crc32a.hpp"
#include "c_plus_plus_serializer.h"
#include "exclusive-lock-file.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

// crypto_dbmgr.hpp
namespace cryptoAL
{
namespace db
{
	const bool SHOWDEBUG = false;

    class db_mgr
    {
    public:
		std::map<std::string, bool> map_private_key_rsa_update;
		std::map<std::string, bool> map_private_key_ecc_update;
		std::map<std::string, bool> map_private_key_eccdom_update;
		std::map<std::string, bool> map_private_key_hh_encode_update;
		std::map<std::string, bool> map_private_key_hh_decode_update;

		std::map<std::string, std::map<std::string, cryptoAL::rsa::rsa_key>*> 	multimap_rsa;
		std::map<std::string, std::map<std::string, cryptoAL::ecc_key>*>  		multimap_ecc;
		std::map<std::string, std::map<std::string, cryptoAL::ecc_domain>*>  	multimap_eccdom; //read only ?
		std::map<std::string, std::map<uint32_t, cryptoAL::history_key>*>  	    multimap_hh_encode;
		std::map<std::string, std::map<uint32_t, cryptoAL::history_key>*>  	    multimap_hh_decode;

		crypto_cfg& cfg;

        db_mgr(crypto_cfg& c) : cfg(c) {}

		~db_mgr()
		{
			if (SHOWDEBUG) std::cout << "~db_mgr()" << std::endl;
			flush(true);
		}

		void flush(bool merge_with_file = false)
		{
			if (SHOWDEBUG) std::cout << "flush merge_with_file " << merge_with_file  << std::endl;

			update(merge_with_file);
			clear();
		}

		bool get_eccdomain_map(	const std::string& pathdb,
                          		std::map<std::string, cryptoAL::ecc_domain>** map_ecc_domain,
                            	bool merge_with_file = false)
		{
			if (SHOWDEBUG) std::cout << "get_eccdomain_map " << pathdb << std::endl;
			if (SHOWDEBUG) std::cout << "merge_with_file " << merge_with_file << std::endl;

			(*map_ecc_domain) = nullptr;
			if (file_util::fileexists(pathdb) == false)
			{
				std::map<std::string, cryptoAL::ecc_domain> pmapnone;
				std::ofstream outfile;
				outfile.open(pathdb, std::ios_base::out);
				outfile << bits(pmapnone);
				outfile.close();
			}

			if (file_util::is_file_private(pathdb) == false)
				return false;

			bool r = true;
			std::map<std::string, cryptoAL::ecc_domain>* pmap = nullptr;

			if (multimap_eccdom.find(pathdb) == multimap_eccdom.end())
			{
				if (file_util::fileexists(pathdb))
				{
					bool lock_ok = false;
					int cnt = 0;
					while (lock_ok == false)
					{
						try
						{
							exclusive_lock_file lockdb(pathdb + ".lock");
							lock_ok = true; // IN LOCK

							pmap = new std::map<std::string, cryptoAL::ecc_domain>;

							std::ifstream infile;
							infile.open(pathdb, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_eccdom[pathdb] = pmap;
						}
						catch(...)
						{
							lock_ok = false;
						}

						if (lock_ok)
						{
							break;
						}
						cnt++;

						std::this_thread::sleep_for(std::chrono::seconds(1)); //retrying in 1 sec... 
						if (cnt > 10)
						{
							if (SHOWDEBUG) std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
							break;
						}
					}
				}
				else
				{
                    std::cerr << "ERROR no file " << pathdb << std::endl;
					r = false;
				}
			}
			else
			{
				pmap = multimap_eccdom[pathdb];

				if (merge_with_file)
				{
					pmap = multimap_eccdom[pathdb];
					merge_eccdom(false, pathdb, multimap_eccdom, pmap);
					pmap = multimap_eccdom[pathdb];
				}
			}

			if (r == true)
			{
				(*map_ecc_domain) = pmap;
			}
			return r;
		}

		bool get_ecckey_map(const std::string& pathdb,
                          	std::map<std::string, cryptoAL::ecc_key>** map_ecc,
                            bool merge_with_file = false)
		{
			if (SHOWDEBUG) std::cout << "get_ecckey_map " << pathdb << std::endl;
			if (SHOWDEBUG) std::cout << "merge_with_file " << merge_with_file << std::endl;

			(*map_ecc) = nullptr;
			if (file_util::fileexists(pathdb) == false)
			{
				std::map<std::string, cryptoAL::ecc_key> pmapnone;
				std::ofstream outfile;
				outfile.open(pathdb, std::ios_base::out);
				outfile << bits(pmapnone);
				outfile.close();
			}

			if (file_util::is_file_private(pathdb) == false)
				return false;

			bool r = true;
			std::map<std::string, cryptoAL::ecc_key>* pmap = nullptr;

			if (multimap_ecc.find(pathdb) == multimap_ecc.end())
			{
				if (file_util::fileexists(pathdb))
				{
					// load
					bool lock_ok = false;
					int cnt = 0;
					while (lock_ok == false)
					{
						try
						{
							exclusive_lock_file lockdb(pathdb + ".lock");
							lock_ok = true; // IN LOCK

							pmap = new std::map<std::string, cryptoAL::ecc_key>;

							std::ifstream infile;
							infile.open(pathdb, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_ecc[pathdb] = pmap;
						}
						catch(...)
						{
							lock_ok = false;
						}

						if (lock_ok)
						{
							break;
						}
						cnt++;

						std::this_thread::sleep_for(std::chrono::seconds(1)); //retrying in 1 sec... 
						if (cnt > 10)
						{
							if (SHOWDEBUG) std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
							break;
						}
					}
				}
				else
				{
                    std::cerr << "ERROR no file " << pathdb << std::endl;
					r = false;
				}
			}
			else
			{
				pmap = multimap_ecc[pathdb];

				if (merge_with_file)
				{
					pmap = multimap_ecc[pathdb];
					merge_ecckey(false, pathdb, multimap_ecc, pmap);
					pmap = multimap_ecc[pathdb];
				}
			}

			if (r == true)
			{
				(*map_ecc) = pmap;
			}
			return r;
		}

		bool get_rsa_map(   const std::string& pathdb,
                            std::map<std::string, cryptoAL::rsa::rsa_key>** map_rsa,
                            bool merge_with_file = false)
		{
			if (SHOWDEBUG) std::cout << "get_rsa_map " << pathdb << std::endl;
			if (SHOWDEBUG) std::cout << "merge_with_file " << merge_with_file << std::endl;

			(*map_rsa) = nullptr;
			if (file_util::fileexists(pathdb) == false)
			{
				std::map<std::string, cryptoAL::rsa::rsa_key> pmapnone;
				std::ofstream outfile;
				outfile.open(pathdb, std::ios_base::out);
				outfile << bits(pmapnone);
				outfile.close();
			}

			if (file_util::is_file_private(pathdb) == false)
				return false;

			bool r = true;
			std::map<std::string, cryptoAL::rsa::rsa_key>* pmap = nullptr;

			if (multimap_rsa.find(pathdb) == multimap_rsa.end())
			{
				if (file_util::fileexists(pathdb))
				{
					// load
					bool lock_ok = false;
					int cnt = 0;
					while (lock_ok == false)
					{
						try
						{
							exclusive_lock_file lockdb(pathdb + ".lock");
							lock_ok = true; // IN LOCK

							pmap = new std::map<std::string, cryptoAL::rsa::rsa_key>;

							std::ifstream infile;
							infile.open(pathdb, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_rsa[pathdb] = pmap;
						}
						catch(...)
						{
							lock_ok = false;
						}

						if (lock_ok)
						{
							break;
						}
						cnt++;

						std::this_thread::sleep_for(std::chrono::seconds(1)); //retrying in 1 sec... 
						if (cnt > 10)
						{
							if (SHOWDEBUG) std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
							break;
						}
					}
				}
				else
				{
                    std::cerr << "ERROR no file " << pathdb << std::endl;
					r = false;
				}
			}
			else
			{
				pmap = multimap_rsa[pathdb];

				if (merge_with_file)
				{
					pmap = multimap_rsa[pathdb];
					merge_rsa(false, pathdb, multimap_rsa, pmap);
					pmap = multimap_rsa[pathdb];
				}
			}

			if (r == true)
			{
				(*map_rsa) = pmap;
			}
			return r;
		}

		void mark_ecckey_as_changed(const std::string& pathdb)
		{
			if (file_util::is_file_private(pathdb) == false)
			{
				if (SHOWDEBUG) std::cerr << "mark_ecckey_as_changed FAILED " << pathdb  << std::endl;
			}
			else
			{
				map_private_key_ecc_update[pathdb] = true;
			}
		}

		void mark_rsa_as_changed(const std::string& pathdb)
		{
			if (file_util::is_file_private(pathdb) == false)
			{
				if (SHOWDEBUG) std::cerr << "mark_rsa_as_changed FAILED " << pathdb  << std::endl;
			}
			else
			{
				map_private_key_rsa_update[pathdb] = true;
			}
		}

		void merge_ecckey(	bool already_in_lock,
                        	const std::string& pathdb,
							std::map<std::string, std::map<std::string, cryptoAL::ecc_key>*>& 	multimap_ecckey,
							std::map<std::string, cryptoAL::ecc_key>* ptr_in_memory_map)
		{
			if (already_in_lock == true)
			{
				// read file into a temp map
				std::map<std::string, cryptoAL::ecc_key>* temp_map = new std::map<std::string, cryptoAL::ecc_key>;
				{
					std::ifstream infile;
					infile.open(pathdb, std::ios_base::in);
					infile >> bits(*temp_map);
					infile.close();
				}

				if (ptr_in_memory_map != nullptr)
				{
					for(auto& [keyname, k] : (*ptr_in_memory_map))
					{
						if (temp_map->find(keyname) == temp_map->end())
						{
							if (SHOWDEBUG) std::cout << "NEW KEY only in memory " << keyname << std::endl;
							temp_map->insert(std::make_pair(keyname,  k));
						}
					}
				}
				
				// swap
				multimap_ecckey[pathdb] = temp_map;
				if (ptr_in_memory_map != nullptr)
					delete ptr_in_memory_map;
			}
			else
			{
				bool lock_ok = false;
				int cnt = 0;
				while (lock_ok == false)
				{
					try
					{
						exclusive_lock_file lockdb(pathdb + ".lock");
						lock_ok = true; // IN LOCK

						// read file into a temp map
						std::map<std::string, cryptoAL::ecc_key>* temp_map = new std::map<std::string, cryptoAL::ecc_key>;
						{
							std::ifstream infile;
							infile.open(pathdb, std::ios_base::in);
							infile >> bits(*temp_map);
							infile.close();
						}
						if (ptr_in_memory_map != nullptr)
						{
							for(auto& [keyname, k] : (*ptr_in_memory_map))
							{
								if (temp_map->find(keyname) == temp_map->end())
								{
									if (SHOWDEBUG) std::cout << "NEW KEY only in memory " << keyname << std::endl;
									temp_map->insert(std::make_pair(keyname,  k));
								}
							}
						}
						// swap
						multimap_ecckey[pathdb] = temp_map;
						if (ptr_in_memory_map != nullptr)
							delete ptr_in_memory_map;
					}
					catch(...)
					{
						lock_ok = false;
					}

					if (lock_ok)
					{
						break;
					}
					cnt++;

					std::this_thread::sleep_for(std::chrono::seconds(1)); //retrying in 1 sec... 
					if (cnt > 10)
					{
						if (SHOWDEBUG) std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
						break;
					}
				}
			}
		}

		void merge_eccdom(	bool already_in_lock,
                        	const std::string& pathdb,
							std::map<std::string, std::map<std::string, cryptoAL::ecc_domain>*>& multimap_eccdom,
							std::map<std::string, cryptoAL::ecc_domain>* ptr_in_memory_map)
		{
			//...read only
		}

		void merge_rsa(	bool already_in_lock,
                        const std::string& pathdb,
						std::map<std::string, std::map<std::string, cryptoAL::rsa::rsa_key>*>& 	multimap_rsa,
						std::map<std::string, cryptoAL::rsa::rsa_key>* ptr_in_memory_map)
		{
			// some changes may have been done in file by other process
			// take status of keys from file
			// add keys from memory

			if (already_in_lock == true)
			{
				// read file into a temp map
				std::map<std::string, cryptoAL::rsa::rsa_key>* temp_map = new std::map<std::string, cryptoAL::rsa::rsa_key>;
				{
					std::ifstream infile;
					infile.open(pathdb, std::ios_base::in);
					infile >> bits(*temp_map);
					infile.close();
				}

				if (ptr_in_memory_map != nullptr)
				{
					for(auto& [keyname, k] : (*ptr_in_memory_map))
					{
						if (temp_map->find(keyname) == temp_map->end())
						{
							if (SHOWDEBUG) std::cout << "NEW KEY only in memory " << keyname << std::endl;
							temp_map->insert(std::make_pair(keyname,  k));
						}
					}
				}
				
				// swap
				multimap_rsa[pathdb] = temp_map;
				if (ptr_in_memory_map != nullptr)
					delete ptr_in_memory_map;
			}
			else
			{
				bool lock_ok = false;
				int cnt = 0;
				while (lock_ok == false)
				{
					try
					{
						exclusive_lock_file lockdb(pathdb + ".lock");
						lock_ok = true; // IN LOCK

						// read file into a temp map
						std::map<std::string, cryptoAL::rsa::rsa_key>* temp_map = new std::map<std::string, cryptoAL::rsa::rsa_key>;
						{
							std::ifstream infile;
							infile.open(pathdb, std::ios_base::in);
							infile >> bits(*temp_map);
							infile.close();
						}

						if (ptr_in_memory_map != nullptr)
						{
							for(auto& [keyname, k] : (*ptr_in_memory_map))
							{
								if (temp_map->find(keyname) == temp_map->end())
								{
									temp_map->insert(std::make_pair(keyname,  k));
								}
							}
						}

						// swap
						multimap_rsa[pathdb] = temp_map;
						if (ptr_in_memory_map != nullptr)
							delete ptr_in_memory_map;
					}
					catch(...)
					{
						lock_ok = false;
					}

					if (lock_ok)
					{
						break;
					}
					cnt++;

					std::this_thread::sleep_for(std::chrono::seconds(1)); //retrying in 1 sec... 
					if (cnt > 10)
					{
						if (SHOWDEBUG) std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
						break;
					}
				}
			}
		}

		void update(bool merge_with_file = false)
		{
			if (SHOWDEBUG) std::cout << "update " << std::endl;
			if (SHOWDEBUG) std::cout << "update merge_with_file " << merge_with_file  << std::endl;

            try
            {
				//multimap_eccdom read only ?

                // save
                for(auto& [pathdb, b] : map_private_key_rsa_update)
                {
                    if (b == true)
                    {
                        if (multimap_rsa.find(pathdb) != multimap_rsa.end())
                        {
                            std::map<std::string, cryptoAL::rsa::rsa_key>* pmap = multimap_rsa[pathdb];
                            if (pmap!=nullptr)
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true; // IN LOCK

										{
											std::ofstream outfile;
											outfile.open(pathdb + ".bck", std::ios_base::out);
											outfile << bits(*pmap);
											outfile.close();
										}

										if (merge_with_file)
										{
											merge_rsa(true, pathdb, multimap_rsa, pmap);
											pmap = multimap_rsa[pathdb];
										}

										{
											std::ofstream out;
											out.open(pathdb, std::ios_base::out);
											out << bits(*pmap);
											out.close();
										}
										map_private_key_rsa_update[pathdb] = false;
									}
									catch(...)
									{
										lock_ok = false;
									}

									if (lock_ok)
									{
										break;
									}
									cnt++;

									std::this_thread::sleep_for(std::chrono::seconds(1)); //retrying in 1 sec... 
									if (cnt > 10)
									{
										if (SHOWDEBUG) std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
										break;
									}
								}
                            }
							else
							{
								if (SHOWDEBUG) std::cout << "update pmap = multimap_rsa[pathdb] == nullptr" << std::endl;
							}
                        }
						else
						{
							if (SHOWDEBUG) std::cout << "update no multimap_rsa[pathdb]" << std::endl;
						}
                    }
					else
					{
						if (SHOWDEBUG) std::cout << "update no changes to save " << pathdb << std::endl;
					}
                }

                for(auto& [pathdb, b] : map_private_key_ecc_update)
                {
                    if (b == true)
                    {
                        if (multimap_ecc.find(pathdb) != multimap_ecc.end())
                        {
                            std::map<std::string, cryptoAL::ecc_key>* pmap = multimap_ecc[pathdb];
                            if (pmap!=nullptr)
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true;

										// backup
										{
											std::ofstream outfile;
											outfile.open(pathdb + ".bck", std::ios_base::out);
											outfile << bits(*pmap);
											outfile.close();
										}

										// save
										{
											std::ofstream out;
											out.open(pathdb, std::ios_base::out);
											out << bits(*pmap);
											out.close();
										}

										map_private_key_ecc_update[pathdb] = false;
									}
									catch(...)
									{
										lock_ok = false;
									}

									if (lock_ok)
									{
										break;
									}
									cnt++;

									std::this_thread::sleep_for(std::chrono::seconds(1));

									if (cnt > 10)
									{
										std::cerr << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
										break;
									}
								}
                            }
                        }
                    }
                }

                for(auto& [pathdb, b] : map_private_key_hh_decode_update)
                {
                    if (b == true)
                    {
                        if (multimap_hh_decode.find(pathdb) != multimap_hh_decode.end())
                        {
                            std::map<uint32_t, cryptoAL::history_key>* pmap = multimap_hh_decode[pathdb];
                            if (pmap!=nullptr)
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true;

										// backup
										{
											std::ofstream outfile;
											outfile.open(pathdb + ".bck", std::ios_base::out);
											outfile << bits(*pmap);
											outfile.close();
										}

										// save
										{
											std::ofstream out;
											out.open(pathdb, std::ios_base::out);
											out << bits(*pmap);
											out.close();
										}

										map_private_key_hh_decode_update[pathdb] = false;
									}
									catch(...)
									{
										lock_ok = false;
									}

									if (lock_ok)
									{
										break;
									}
									cnt++;

									std::this_thread::sleep_for(std::chrono::seconds(1));

									if (cnt > 10)
									{
										std::cerr << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
										break;
									}
								}
                            }
                        }
                    }
                }

                for(auto& [pathdb, b] : map_private_key_hh_encode_update)
                {
                    if (b == true)
                    {
                        if (multimap_hh_encode.find(pathdb) != multimap_hh_encode.end())
                        {
                            std::map<uint32_t, cryptoAL::history_key>* pmap = multimap_hh_encode[pathdb];
                            if (pmap!=nullptr)
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true;

										// backup
										{
											std::ofstream outfile;
											outfile.open(pathdb + ".bck", std::ios_base::out);
											outfile << bits(*pmap);
											outfile.close();
										}

										{
											std::ofstream out;
											out.open(pathdb, std::ios_base::out);
											out << bits(*pmap);
											out.close();
										}

										map_private_key_hh_encode_update[pathdb] = false;
									}
									catch(...)
									{
										lock_ok = false;
									}

									if (lock_ok)
									{
										break;
									}
									cnt++;

									std::this_thread::sleep_for(std::chrono::seconds(1));

									if (cnt > 10)
									{
										std::cerr << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
										break;
									}
								}
                            }
                        }
                    }
                }
			}
			catch(...)
			{
                if (SHOWDEBUG) std::cerr << "db_mgr update EXCEPTION " << std::endl;
			}
		}

		void clear()
		{
			if (SHOWDEBUG) std::cout << "clear " << std::endl;
            try
            {
                // delete memory
                for(auto& [pathdb, m] : multimap_rsa)
                {
                    if (m != nullptr)
                    {
                        delete m;
                        m = nullptr;
						multimap_rsa[pathdb] = nullptr;
                    }
                }
				multimap_rsa.clear();

                for(auto& [pathdb, m] : multimap_ecc)
                {
                    if (m != nullptr)
                    {
                        delete m;
                        m = nullptr;
						multimap_ecc[pathdb] = nullptr;
                    }
                }
				multimap_ecc.clear();

				for(auto& [pathdb, m] : multimap_eccdom)
                {
                    if (m != nullptr)
                    {
                        delete m;
                        m = nullptr;
						multimap_eccdom[pathdb] = nullptr;
                    }
                }
				multimap_eccdom.clear();

                for(auto& [pathdb, m] : multimap_hh_decode)
                {
                    if (m != nullptr)
                    {
                        delete m;
                        m = nullptr;
						multimap_hh_decode[pathdb] = nullptr;
                    }
                }
				multimap_hh_decode.clear();

                for(auto& [pathdb, m] : multimap_hh_encode)
                {
                    if (m != nullptr)
                    {
                        delete m;
                        m = nullptr;
						multimap_hh_encode[pathdb] = nullptr;
                    }
                }
				multimap_hh_encode.clear();

				map_private_key_rsa_update.clear();
				map_private_key_ecc_update.clear();
				map_private_key_hh_encode_update.clear();
				map_private_key_hh_decode_update.clear();
			}
			catch(...)
			{
                if (SHOWDEBUG) std::cerr << "db_mgr clear EXCEPTION " << std::endl;
			}
		}

		bool add_to_usage_count_hh_encode(uint32_t keyseq, const std::string& pathdb)
		{
			if (file_util::is_file_private(pathdb) == false)
				return false;

            bool r = true;
			std::map<uint32_t, cryptoAL::history_key>* pmap  = nullptr;

			if (multimap_hh_encode.find(pathdb) == multimap_hh_encode.end())
			{
				if (file_util::fileexists(pathdb))
				{
					// load
					pmap = new std::map<uint32_t, cryptoAL::history_key>;

					std::ifstream infile;
					infile.open(pathdb, std::ios_base::in);
					infile >> bits(*pmap);
					infile.close();

					multimap_hh_encode[pathdb] = pmap;
				}
				else
				{
                    std::cerr << "ERROR no file " << pathdb << std::endl;
					r = false;
				}
			}

			if (r)
			{
				if (pmap!=nullptr)
				{
					std::map<uint32_t, cryptoAL::history_key>& refmap = *pmap;
					for(auto& [userkey, k] : refmap)
					{
						if (userkey == keyseq)
						{
							k.add_to_usage_count();
							map_private_key_hh_encode_update[pathdb] = true;
							break;
						}
					}
				}
			}

            return r;
		}

		bool add_to_usage_count_hh_decode(uint32_t keyseq, const std::string& pathdb)
		{
			if (file_util::is_file_private(pathdb) == false)
				return false;

			bool r = true;
			std::map<uint32_t, cryptoAL::history_key>* pmap  = nullptr;

			if (multimap_hh_decode.find(pathdb) == multimap_hh_decode.end())
			{
				if (file_util::fileexists(pathdb))
				{
					// load
					pmap = new std::map<uint32_t, cryptoAL::history_key>;

					std::ifstream infile;
					infile.open(pathdb, std::ios_base::in);
					infile >> bits(*pmap);
					infile.close();

					multimap_hh_decode[pathdb] = pmap;
				}
				else
				{
                    std::cerr << "ERROR no file " << pathdb << std::endl;
					r = false;
				}
			}

			if (r)
			{
				if (pmap!=nullptr)
				{
					std::map<uint32_t, cryptoAL::history_key>& refmap = *pmap;
					for(auto& [userkey, k] : refmap)
					{
						if (userkey == keyseq)
						{
							k.add_to_usage_count();
							map_private_key_hh_decode_update[pathdb] = true;
							break;
						}
					}
				}
			}

            return r;
		}

		bool add_to_usage_count_rsa(const std::string& key_name, const std::string& pathdb)
		{
			if (file_util::is_file_private(pathdb) == false)
				return false;

			bool r = true;
			std::map<std::string, cryptoAL::rsa::rsa_key>* pmap  = nullptr;

			if (multimap_rsa.find(pathdb) == multimap_rsa.end())
			{
				if (file_util::fileexists(pathdb))
				{
					// load
					pmap = new std::map<std::string, cryptoAL::rsa::rsa_key>;

					std::ifstream infile;
					infile.open(pathdb, std::ios_base::in);
					infile >> bits(*pmap);
					infile.close();

					multimap_rsa[pathdb] = pmap;
				}
				else
				{
                    std::cerr << "ERROR no file " << pathdb << std::endl;
					r = false;
				}
			}

			if (r)
			{
				pmap = multimap_rsa[pathdb];
				if (pmap!=nullptr)
				{
					std::map<std::string, cryptoAL::rsa::rsa_key>& refmap = *pmap;
					for(auto& [userkey, k] : refmap)
					{
						if (userkey == key_name)
						{
							k.add_to_usage_count();
							map_private_key_rsa_update[pathdb] = true;
							break;
						}
					}
				}
			}
			return r;
		}

		bool add_to_usage_count_ecc(const std::string& key_name, const std::string& pathdb)
		{
			if (file_util::is_file_private(pathdb) == false)
			{
				std::cerr << "ERROR no file: " << pathdb << std::endl;
				return false;
			}

            bool r = true;
			std::map<std::string, cryptoAL::ecc_key>* pmap  = nullptr;

			if (multimap_ecc.find(pathdb) == multimap_ecc.end())
			{
				if (file_util::fileexists(pathdb))
				{
					// load
					pmap = new std::map<std::string, cryptoAL::ecc_key>;

					std::ifstream infile;
					infile.open(pathdb, std::ios_base::in);
					infile >> bits(*pmap);
					infile.close();

					multimap_ecc[pathdb] = pmap;
				}
				else
				{
                    std::cerr << "ERROR no file " << pathdb << std::endl;
					r = false;
				}
			}

			if (r)
			{
				pmap = multimap_ecc[pathdb];
				if (pmap!=nullptr)
				{
					std::map<std::string, cryptoAL::ecc_key>& refmap = *pmap;
					for(auto& [userkey, k] : refmap)
					{
						if (userkey == key_name)
						{
							k.add_to_usage_count();
							map_private_key_ecc_update[pathdb] = true;
							break;
						}
					}
				}
				else
				{
                    std::cerr << "ERROR no file in memory " << pathdb << std::endl;
					r = false;
				}
			}

            return r;
		}

		bool find_history_key_by_sha(const std::string& key_sha, const std::string& local_histo_db,
															 history_key& kout, uint32_t& seq, bool is_decode)
		{
			bool found = false;
			std::map<uint32_t, cryptoAL::history_key>* pmap  = nullptr;

			if (file_util::fileexists(local_histo_db) == true)
			{
				if (file_util::is_file_private(local_histo_db) == true)
				{
					if (is_decode)
					{
						if (multimap_hh_decode.find(local_histo_db) == multimap_hh_decode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_decode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_decode[local_histo_db];
						}
					}
					else
					{
						if (multimap_hh_encode.find(local_histo_db) == multimap_hh_encode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_encode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_encode[local_histo_db];
						}
					}

					if (pmap!=nullptr)
					{
						std::map<uint32_t, history_key>& map_histo = *pmap;

						for(auto& [seqkey, k] : map_histo)
						{
							if (k.data_sha[0] == key_sha)
							{
								found = true;
								kout = k;
								seq = seqkey;
								break;
							}
						}
					}
				}
			}
			return found;
		}

		bool save_histo_key(const history_key& k, const std::string& local_histo_db, bool is_decode)
		{
			bool ok = true;
			bool toupdate = false;
			std::map<uint32_t, cryptoAL::history_key>* pmap  = nullptr;

			if (file_util::fileexists(local_histo_db) == true)
			{
				if (file_util::is_file_private(local_histo_db) == true)
				{
					if (is_decode)
					{
						if (multimap_hh_decode.find(local_histo_db) == multimap_hh_decode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_decode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_decode[local_histo_db];
						}
					}
					else
					{
						if (multimap_hh_encode.find(local_histo_db) == multimap_hh_encode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_encode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_encode[local_histo_db];
						}
					}

					if (pmap!=nullptr)
					{
						std::map<uint32_t, history_key>& map_histo = *pmap;

						for(auto& [seqkey, k] : map_histo)
						{
							if (seqkey == k.sequence)
							{
								toupdate = true;
								break;
							}
						}

						if (toupdate)
						{
						}
						else
						{
						}

						if (is_decode)
							map_private_key_hh_decode_update[local_histo_db] = true;
						else
							map_private_key_hh_encode_update[local_histo_db] = true;

						map_histo[k.sequence] = k; // new or update
					}
				}
			}
			return ok;
		}

	    bool get_history_key(const uint32_t& seq, const std::string& local_histo_db, history_key& kout, bool is_decode)
		{
			bool found = false;
			std::map<uint32_t, cryptoAL::history_key>* pmap  = nullptr;

			if (file_util::fileexists(local_histo_db) == true)
			{
				if (file_util::is_file_private(local_histo_db) == true)
				{
					if (is_decode)
					{
						if (multimap_hh_decode.find(local_histo_db) == multimap_hh_decode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_decode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_decode[local_histo_db];
						}
					}
					else
					{
						if (multimap_hh_encode.find(local_histo_db) == multimap_hh_encode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_encode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_encode[local_histo_db];
						}
					}

					if (pmap!=nullptr)
					{
						std::map<uint32_t, history_key>& map_histo = *pmap;

						for(auto& [seqkey, k] : map_histo)
						{
							if (seqkey == seq)
							{
								found = true;
								kout = k;
								break;
							}
						}
					}
				}
				else
				{
				}
			}
			else
			{
			}
			return found;
		}

		bool get_next_seq_histo(uint32_t& out_seq, const std::string& local_histo_db, bool is_decode)
		{
			bool ok = true;
			uint32_t maxseq=0;
			out_seq = 0;
			std::map<uint32_t, cryptoAL::history_key>* pmap  = nullptr;

			if (file_util::fileexists(local_histo_db) == true)
			{
				if (file_util::is_file_private(local_histo_db) == true)
				{
					if (is_decode)
					{
						if (multimap_hh_decode.find(local_histo_db) == multimap_hh_decode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_decode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_decode[local_histo_db];
						}
					}
					else
					{
						if (multimap_hh_encode.find(local_histo_db) == multimap_hh_encode.end())
						{
							// load
							pmap = new std::map<uint32_t, cryptoAL::history_key>;

							std::ifstream infile;
							infile.open(local_histo_db, std::ios_base::in);
							infile >> bits(*pmap);
							infile.close();

							multimap_hh_encode[local_histo_db] = pmap;
						}
						else
						{
							pmap = multimap_hh_encode[local_histo_db];
						}
					}

					if (pmap!=nullptr)
					{
						std::map<uint32_t, history_key>& map_histo = *pmap;

						for(auto& [seqkey, k] : map_histo)
						{
							if (seqkey > maxseq)
							{
								maxseq = seqkey;
								out_seq = maxseq;
							}
						}
						out_seq++;
					}
				}
				else
				{
					out_seq = 1;
				}
			}
			else
			{
				out_seq = 1;
				//std::cout << "WARNING no histo file (creating historical sequence 1) in : " << local_histo_db << std::endl;
			}

			return ok;
		}


    };

}
}
#endif
