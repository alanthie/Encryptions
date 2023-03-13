#ifndef CRYPTO_HISTORY_H_INCLUDED
#define CRYPTO_HISTORY_H_INCLUDED

#include "base_const.hpp"
#include <map>
#include <string>
#include "c_plus_plus_serializer.h"

namespace cryptoAL
{
    struct history_key
    {
        history_key()
        {
        };

		void update_seq(const uint32_t& seq)
		{
			sequence = seq;
		}

        history_key(uint32_t dsize, const std::string& a, const std::string& b, const std::string& c)
        {
            data_size = dsize;
            data_sha[0] = a; // hash full
            data_sha[1] = b; // hash half
            data_sha[2] = c; // hash second half

			sequence = 0;
        }

		uint32_t sequence = 0; // index
        uint32_t data_size;
        std::string data_sha[3];

        friend std::ostream& operator<<(std::ostream &out, Bits<history_key & > my)
        {
            out << bits(my.t.sequence) << bits(my.t.data_size) << bits(my.t.data_sha[0]) << bits(my.t.data_sha[1]) << bits(my.t.data_sha[2]);
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<history_key &> my)
        {
            in >> bits(my.t.sequence) >> bits(my.t.data_size) >> bits(my.t.data_sha[0]) >> bits(my.t.data_sha[1]) >> bits(my.t.data_sha[2]);
            return (in);
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
			std::cout << "ERROR no seq in histofile: " << seq << " " << local_histo_db << std::endl;
		}

		return found;
	}

	bool get_next_seq(uint32_t& out_seq, const std::string& local_histo_db)
	{
		bool ok = true;
		uint32_t maxseq=0;

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
		}
		else
		{
			std::cout << "ERROR no histo file: " << local_histo_db << std::endl;
			ok = false;
		}

		return ok;
	}

}
#endif
