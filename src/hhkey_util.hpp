#ifndef HHKEY_UTIL_HPP_INCLUDED
#define HHKEY_UTIL_HPP_INCLUDED

#include "crypto_const.hpp"
#include "crypto_ecckey.hpp"
#include "data.hpp"
#include "crypto_key_parser.hpp"
#include "random_engine.hpp"
#include "crc32a.hpp"
#include "c_plus_plus_serializer.h"
#include "qa/rsa_gen.hpp"
#include "crypto_dbmgr.hpp"

namespace cryptoAL
{
namespace hhkey_util
{

	[[maybe_unused]] static bool find_history_key_by_sha(const std::string& key_sha, const std::string& local_histo_db, 
														 history_key& kout, uint32_t& seq, cryptoAL::db::db_mgr& dbmgr, bool is_decode)
	{
		bool found = false;

		if (file_util::fileexists(local_histo_db) == true)
		{
			if (file_util::is_file_private(local_histo_db) == true)
			{
				return dbmgr.find_history_key_by_sha(key_sha, local_histo_db, kout, seq, is_decode);
			}
			else
			{
				std::map<uint32_t, history_key> map_histo;

				std::ifstream infile;
				infile.open (local_histo_db, std::ios_base::in);
				infile >> bits(map_histo);
				infile.close();

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
		return found;
	}

	[[maybe_unused]] static bool save_histo_key(const history_key& k, const std::string& local_histo_db, cryptoAL::db::db_mgr& dbmgr, bool is_decode)
	{
		bool ok = true;
		bool toupdate = false;

		if (file_util::fileexists(local_histo_db) == true)
		{
			if (file_util::is_file_private(local_histo_db) == true)
			{
				return dbmgr.save_histo_key(k, local_histo_db, is_decode);
			}
			else
			{
				std::map<uint32_t, history_key> map_histo;

				std::ifstream infile;
				infile.open (local_histo_db, std::ios_base::in);
				infile >> bits(map_histo);
				infile.close();

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
				map_histo[k.sequence] = k;

				// backup
				if (file_util::fileexists(local_histo_db) == true)
				{
					std::ofstream outfile;
					outfile.open(local_histo_db + ".bck", std::ios_base::out);
					outfile << bits(map_histo);
					outfile.close();
				}

				// save
				{
					std::ofstream outfile;
					outfile.open(local_histo_db, std::ios_base::out);
					outfile << bits(map_histo);
					outfile.close();
				}
			}
		}
		else
		{
			ok = false;
		}
		return ok;
	}

	[[maybe_unused]] static bool get_history_key(const uint32_t& seq, const std::string& local_histo_db, history_key& kout, cryptoAL::db::db_mgr& dbmgr, bool is_decode)
	{
		bool found = false;

		if (file_util::fileexists(local_histo_db) == true)
		{
			if (file_util::is_file_private(local_histo_db) == true)
			{
				return dbmgr.get_history_key(seq, local_histo_db, kout, is_decode);
			}
			else
			{
				std::map<uint32_t, history_key> map_histo;

				std::ifstream infile;
				infile.open (local_histo_db, std::ios_base::in);
				infile >> bits(map_histo);
				infile.close();

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
			std::cout << "WARNING no seq in histo file: " << seq << " " << local_histo_db << std::endl;
		}
		return found;
	}

	[[maybe_unused]] static bool get_next_seq_histo(uint32_t& out_seq, const std::string& local_histo_db, cryptoAL::db::db_mgr& dbmgr, bool is_decode)
	{
		bool ok = true;
		uint32_t maxseq=0;
		out_seq = 0;
		
		if (file_util::fileexists(local_histo_db) == false)
		{
			std::map<uint32_t, history_key> map_histo;
			std::ofstream outstream;
            outstream.open(local_histo_db, std::ios_base::out);
			outstream << bits(map_histo);
			outstream.close();
		}
			
		if (file_util::fileexists(local_histo_db) == true)
		{
			if (file_util::is_file_private(local_histo_db) == true)
			{
				return dbmgr.get_next_seq_histo(out_seq, local_histo_db, is_decode);
			}
			else
			{
				std::map<uint32_t, history_key> map_histo;

				std::ifstream infile;
				infile.open (local_histo_db, std::ios_base::in);
				infile >> bits(map_histo);
				infile.close();

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
			//std::cout << "WARNING no histo file (creating historical sequence 1) in : " << local_histo_db << std::endl;
		}

		return ok;
	}

	[[maybe_unused]] static void make_from_file(	cryptoAL::history_key& k, cryptoAL::cryptodata& encrypted_data,
                                                    const std::string& local_histo_db, bool& result,
                                                    cryptoAL::db::db_mgr& dbmgr, bool is_decode)
	{
		if (encrypted_data.buffer.size() < 64) {result=false;return;}
		result = true;
		k.data_size = encrypted_data.buffer.size();

		k.data_sha[0] = k.checksum(encrypted_data, 0, k.data_size - 1, result);
		if(!result) return;

		uint32_t n = k.data_size/2;
		k.data_sha[1] = k.checksum(encrypted_data, 0, n, result);
		if(!result) return;

		if (n > encrypted_data.buffer.size() - 1) n = k.data_size- 1;
		k.data_sha[2] = k.checksum(encrypted_data, n, k.data_size- 1, result);
		if(!result) return;

		result = get_next_seq_histo(k.sequence, local_histo_db, dbmgr, is_decode);
		if(!result) return;

		k.dt = cryptoAL::parsing::get_current_time_and_date();
	}


}
}
#endif
