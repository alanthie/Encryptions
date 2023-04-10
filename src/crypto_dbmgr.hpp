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
		std::map<std::string, bool> map_private_key_hh_encode_update;
		std::map<std::string, bool> map_private_key_hh_decode_update;

		std::map<std::string, std::map<std::string, cryptoAL::rsa::rsa_key>*> 	multimap_rsa;
		std::map<std::string, std::map<std::string, cryptoAL::ecc_key>*>  		multimap_ecc;
		std::map<std::string, std::map<uint32_t, cryptoAL::history_key>*>  	    multimap_hh_encode;
		std::map<std::string, std::map<uint32_t, cryptoAL::history_key>*>  	    multimap_hh_decode;

		crypto_cfg& cfg;

        db_mgr(crypto_cfg& c) : cfg(c) {}

		~db_mgr()
		{
			update();
			clear();
		}

		void update()
		{
            try
            {
                // save
                for(auto& [pathdb, b] : map_private_key_rsa_update)
                {
                    if (b == true)
                    {
                        if (multimap_rsa.find(pathdb) != multimap_rsa.end())
                        {
                            std::map<std::string, cryptoAL::rsa::rsa_key>* pmap = multimap_rsa[pathdb];
                            if ((pmap!=nullptr) && (map_private_key_rsa_update[pathdb] == true))
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true;

										// save
                                		if (SHOWDEBUG) std::cout << "db_mgr saving (lock acquired) " << pathdb << std::endl;

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

									// TODO
									std::cout << "INFO fail to acquire lock  - retrying in 1 sec... " << pathdb + ".lock" << std::endl;
									std::this_thread::sleep_for(std::chrono::seconds(1));

									if (cnt > 10)
									{
										std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
										break;
									}
								}
                            }
                        }
                    }
                }

                for(auto& [pathdb, b] : map_private_key_ecc_update)
                {
                    if (b == true)
                    {
                        if (multimap_ecc.find(pathdb) != multimap_ecc.end())
                        {
                            std::map<std::string, cryptoAL::ecc_key>* pmap = multimap_ecc[pathdb];
                            if ((pmap!=nullptr) && (map_private_key_ecc_update[pathdb] == true))
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true;

										// save
                                		if (SHOWDEBUG) std::cout << "db_mgr saving (lock acquired) " << pathdb << std::endl;

										// backup
										{
											std::ofstream outfile;
											outfile.open(pathdb + ".bck", std::ios_base::out);
											outfile << bits(*pmap);
											outfile.close();
										}

										// save
										if (SHOWDEBUG) std::cout << "db_mgr saving " << pathdb << std::endl;
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

									// TODO
									std::cout << "INFO fail to acquire lock  - retrying in 1 sec... " << pathdb + ".lock" << std::endl;
									std::this_thread::sleep_for(std::chrono::seconds(1));

									if (cnt > 10)
									{
										std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
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
                            if ((pmap!=nullptr) && (map_private_key_hh_decode_update[pathdb] == true))
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true;

										// save
                                		if (SHOWDEBUG) std::cout << "db_mgr saving (lock acquired) " << pathdb << std::endl;

										// backup
										{
											std::ofstream outfile;
											outfile.open(pathdb + ".bck", std::ios_base::out);
											outfile << bits(*pmap);
											outfile.close();
										}

										// save
										if (SHOWDEBUG) std::cout << "db_mgr saving " << pathdb << std::endl;
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

									// TODO
									std::cout << "INFO fail to acquire lock  - retrying in 1 sec... " << pathdb + ".lock" << std::endl;
									std::this_thread::sleep_for(std::chrono::seconds(1));

									if (cnt > 10)
									{
										std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
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
                            if ((pmap!=nullptr) && (map_private_key_hh_encode_update[pathdb] == true))
                            {
								bool lock_ok = false;
								int cnt = 0;
								while (lock_ok == false)
								{
									try
									{
										exclusive_lock_file lockdb(pathdb + ".lock");
										lock_ok = true;

										// save
                                		if (SHOWDEBUG) std::cout << "db_mgr saving (lock acquired) " << pathdb << std::endl;

										// backup
										{
											std::ofstream outfile;
											outfile.open(pathdb + ".bck", std::ios_base::out);
											outfile << bits(*pmap);
											outfile.close();
										}

										// save
										if (SHOWDEBUG) std::cout << "db_mgr saving " << pathdb << std::endl;
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

									// TODO
									std::cout << "INFO fail to acquire lock  - retrying in 1 sec... " << pathdb + ".lock" << std::endl;
									std::this_thread::sleep_for(std::chrono::seconds(1));

									if (cnt > 10)
									{
										std::cout << "ERROR fail to acquire lock " << pathdb + ".lock" << std::endl;
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
            try
            {
                // delete memory
                for(auto& [pathdb, m] : multimap_rsa)
                {
                    if (m != nullptr)
                    {
                        if (SHOWDEBUG) std::cout << "db_mgr deleting in memory " << pathdb  << std::endl;
                        delete m;
                        m = nullptr;
                    }
                }

                for(auto& [pathdb, m] : multimap_ecc)
                {
                    if (m != nullptr)
                    {
                        if (SHOWDEBUG) std::cout << "db_mgr deleting in memory " << pathdb  << std::endl;
                        delete m;
                        m = nullptr;
                    }
                }

                for(auto& [pathdb, m] : multimap_hh_decode)
                {
                    if (m != nullptr)
                    {
                        if (SHOWDEBUG) std::cout << "db_mgr deleting in memory " << pathdb  << std::endl;
                        delete m;
                        m = nullptr;
                    }
                }
                for(auto& [pathdb, m] : multimap_hh_encode)
                {
                    if (m != nullptr)
                    {
                        if (SHOWDEBUG) std::cout << "db_mgr deleting in memory " << pathdb  << std::endl;
                        delete m;
                        m = nullptr;
                    }
                }
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
					if (SHOWDEBUG) std::cout << "db_mgr loading " << pathdb << std::endl;

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

							if (SHOWDEBUG) std::cout << "db_mgr updating usage_count " << pathdb << " " << keyseq << " " << k.usage_count << std::endl;
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
					if (SHOWDEBUG) std::cout << "db_mgr loading " << pathdb << std::endl;

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

							if (SHOWDEBUG) std::cout << "db_mgr updating usage_count " << pathdb << " " << keyseq << " " << k.usage_count << std::endl;
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
					if (SHOWDEBUG) std::cout << "db_mgr loading " << pathdb << std::endl;

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
				if (pmap!=nullptr)
				{
					std::map<std::string, cryptoAL::rsa::rsa_key>& refmap = *pmap;
					for(auto& [userkey, k] : refmap)
					{
						if (userkey == key_name)
						{
							k.add_to_usage_count();
							map_private_key_rsa_update[pathdb] = true;

							if (SHOWDEBUG) std::cout << "db_mgr updating usage_count " << pathdb << " " << key_name << " " << k.usage_count << std::endl;
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
				return false;

            bool r = true;
			std::map<std::string, cryptoAL::ecc_key>* pmap  = nullptr;

			if (multimap_ecc.find(pathdb) == multimap_ecc.end())
			{
				if (file_util::fileexists(pathdb))
				{
					// load
					if (SHOWDEBUG) std::cout << "db_mgr loading " << pathdb << std::endl;

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
				if (pmap!=nullptr)
				{
					std::map<std::string, cryptoAL::ecc_key>& refmap = *pmap;
					for(auto& [userkey, k] : refmap)
					{
						if (userkey == key_name)
						{
							k.add_to_usage_count();
							map_private_key_ecc_update[pathdb] = true;

							if (SHOWDEBUG) std::cout << "db_mgr updating usage_count " << pathdb << " " << key_name << " " << k.usage_count << std::endl;
							break;
						}
					}
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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
							if (SHOWDEBUG) std::cout << "db_mgr loading " << local_histo_db << std::endl;

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
