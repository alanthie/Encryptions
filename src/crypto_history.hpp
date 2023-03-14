#ifndef CRYPTO_HISTORY_H_INCLUDED
#define CRYPTO_HISTORY_H_INCLUDED

#include "base_const.hpp"
#include <map>
#include <string>
#include "c_plus_plus_serializer.h"
#include "data.hpp"
#include "crypto_file.hpp"
#include "crc32a.hpp"

namespace cryptoAL
{
    bool get_next_seq(uint32_t& out_seq, const std::string& local_histo_db);

    struct history_key
    {
        history_key()
        {
        };

		void update_seq(const uint32_t& seq)
		{
			sequence = seq;
			dt = cryptoAL::get_current_time_and_date();
		}

		void make_from_file(cryptodata& encrypted_data, const std::string& local_histo_db, bool& result)
		{
            if (encrypted_data.buffer.size() < 64) {result=false;return;}
			result = true;
			data_size = encrypted_data.buffer.size();

			data_sha[0] = checksum(encrypted_data, 0, data_size - 1, result);
			if(!result) return;

			uint32_t n = data_size/2;
			data_sha[1] = checksum(encrypted_data, 0, n, result);
			if(!result) return;

			if (n > encrypted_data.buffer.size() - 1) n = data_size- 1;
			data_sha[2] = checksum(encrypted_data, n, data_size- 1, result);
			if(!result) return;

			result = get_next_seq(sequence, local_histo_db);
			if(!result) return;

			dt = cryptoAL::get_current_time_and_date();
		}

        history_key(cryptodata& encrypted_data, const std::string& local_histo_db, bool& result)
		{
            make_from_file(encrypted_data, local_histo_db, result);
		}

        history_key(uint32_t dsize, const std::string& a, const std::string& b, const std::string& c)
        {
            data_size = dsize;
            data_sha[0] = a; // hash full
            data_sha[1] = b; // hash half
            data_sha[2] = c; // hash second half

			sequence = 0;
			dt = cryptoAL::get_current_time_and_date();
        }

		uint32_t sequence = 0; // index
        uint32_t data_size = 0;
        std::string data_sha[3] = {""};
		std::string dt;

        friend std::ostream& operator<<(std::ostream &out, Bits<history_key & > my)
        {
            out << bits(my.t.sequence)
				<< bits(my.t.data_size)
				<< bits(my.t.data_sha[0]) << bits(my.t.data_sha[1]) << bits(my.t.data_sha[2])
				<< bits(my.t.dt) ;
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<history_key &> my)
        {
            in 	>> bits(my.t.sequence)
				>> bits(my.t.data_size)
				>> bits(my.t.data_sha[0]) >> bits(my.t.data_sha[1]) >> bits(my.t.data_sha[2])
				>> bits(my.t.dt) ;
            return (in);
        }

		std::string checksum(cryptodata& d, uint32_t from, uint32_t to, bool& result)
		{
            result = true;
            if (from > to) {result=false;return "";}
            if (to >= d.buffer.size()) {result=false;return "";}
            if (to < 16) {result=false;return "";}

            //std::cout << "histo checksum " << from << " to " << to << std::endl;
			SHA256 sha;
			sha.update(reinterpret_cast<const uint8_t*> (&d.buffer.getdata()[from]), to-from+1 );
			uint8_t* digest = sha.digest();
			std::string checksum = SHA256::toString(digest);
			delete[] digest;
			return checksum;
		}
    };

    bool get_history_key(const uint32_t& seq, const std::string& local_histo_db, history_key& kout)
	{
		bool found = false;

		if (fileexists(local_histo_db) == true)
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
		else
		{
			std::cout << "WARNING no seq in histo file: " << seq << " " << local_histo_db << std::endl;
		}

		return found;
	}

	void show_history_key(const std::string& local_histo_db)
	{
		if (fileexists(local_histo_db) == true)
		{
			std::map<uint32_t, history_key> map_histo;

			std::ifstream infile;
			infile.open (local_histo_db, std::ios_base::in);
			infile >> bits(map_histo);
			infile.close();

			for(auto& [seqkey, k] : map_histo)
			{
				std::cout << "[h]" << seqkey << " " << k.data_sha[0] << " " << k.dt << " " << " datasize: " << k.data_size << std::endl;
			}
		}
	}

	bool find_history_key_by_sha(const std::string& key_sha, const std::string& local_histo_db, history_key& kout)
	{
		bool found = false;

		if (fileexists(local_histo_db) == true)
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
					break;
				}
			}
		}
		return found;
	}

	bool get_next_seq(uint32_t& out_seq, const std::string& local_histo_db)
	{
		bool ok = true;
		uint32_t maxseq=0;
		out_seq = 0;

		if (fileexists(local_histo_db) == true)
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
		else
		{
			std::cout << "WARNING no histo file (creating historical sequence 1) in : " << local_histo_db << std::endl;
			out_seq = 1;
		}

		return ok;
	}

	bool save_histo_key(const history_key& k, const std::string& local_histo_db)
	{
		bool ok = true;
		bool toupdate = false;

		std::map<uint32_t, history_key> map_histo;
		if (fileexists(local_histo_db) == true)
		{
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
        }

        if (toupdate)
        {
        }
        else
        {
        }
        map_histo[k.sequence] = k;

        // backup
        if (fileexists(local_histo_db) == true)
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

		return ok;
	}

}
#endif
