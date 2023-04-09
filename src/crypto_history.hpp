#ifndef CRYPTO_HISTORY_H_INCLUDED
#define CRYPTO_HISTORY_H_INCLUDED

#include "crypto_const.hpp"
#include "c_plus_plus_serializer.h"
#include "crc32a.hpp"
#include <map>
#include <string>

namespace cryptoAL
{
    struct history_key
    {
        history_key() {}

		void update_seq(const uint32_t& seq)
		{
            if (seq != sequence)
            {
                sequence = seq;
                dt = cryptoAL::parsing::get_current_time_and_date();
			}
		}

        void update_confirmed(bool b)
		{
            if (b != confirmed)
            {
                confirmed = b;
                dt_confirmed = cryptoAL::parsing::get_current_time_and_date();
			}
		}

        history_key(uint32_t dsize, const std::string& a, const std::string& b, const std::string& c)
        {
			sequence 	= 0;
            data_size 	= dsize;
            data_sha[0] = a; // hash full
            data_sha[1] = b; // hash half
            data_sha[2] = c; // hash second half
			dt = cryptoAL::parsing::get_current_time_and_date();
			confirmed 	= false;
			deleted 	= false;
			usage_count = 0;
			dt_confirmed = "";
        }

		uint32_t 	sequence   	= 0; // index
        uint32_t 	data_size  	= 0;
        std::string data_sha[3] = {""};
		std::string dt  		= "";
		bool 		confirmed 	= false;
		bool 		deleted 	= false;	// marked for deleted
		uint32_t 	usage_count = 0;
		std::string dt_confirmed = "";

		void add_to_usage_count() {usage_count++;}

        friend std::ostream& operator<<(std::ostream &out, Bits<history_key & > my)
        {
            out << bits(my.t.sequence)
				<< bits(my.t.data_size)
				<< bits(my.t.data_sha[0]) << bits(my.t.data_sha[1]) << bits(my.t.data_sha[2])
				<< bits(my.t.dt)
				<< bits(my.t.confirmed)
				<< bits(my.t.deleted)
				<< bits(my.t.usage_count)
				<< bits(my.t.dt_confirmed);
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<history_key &> my)
        {
            in 	>> bits(my.t.sequence)
				>> bits(my.t.data_size)
				>> bits(my.t.data_sha[0]) >> bits(my.t.data_sha[1]) >> bits(my.t.data_sha[2])
				>> bits(my.t.dt)
				>> bits(my.t.confirmed)
				>> bits(my.t.deleted)
				>> bits(my.t.usage_count)
				>> bits(my.t.dt_confirmed);
            return (in);
        }

		std::string checksum(cryptodata& d, uint32_t from, uint32_t to, bool& result)
		{
            result = true;
            if (from > to) {result=false;return "";}
            if (to >= d.buffer.size()) {result=false;return "";}
            if (to < 16) {result=false;return "";}

			SHA256 sha;
			sha.update(reinterpret_cast<const uint8_t*> (&d.buffer.getdata()[from]), to-from+1 );
			uint8_t* digest = sha.digest();
			std::string checksum = SHA256::toString(digest);
			delete[] digest;
			return checksum;
		}
    };

    struct history_key_public
    {
        history_key_public() {}

        friend std::ostream& operator<<(std::ostream &out, Bits<history_key_public & > my)
        {
            out << bits(my.t.data_size)
				<< bits(my.t.data_sha0)
				<< bits(my.t.summary_sha)
				<< bits(my.t.confirmed)
				<< bits(my.t.deleted)
				<< bits(my.t.usage_count)
				<< bits(my.t.dt_confirmed);
            return (out);
        }

        friend std::istream& operator>>(std::istream &in, Bits<history_key_public &> my)
        {
            in 	>> bits(my.t.data_size)
				>> bits(my.t.data_sha0)
				>> bits(my.t.summary_sha)
				>> bits(my.t.confirmed)
				>> bits(my.t.deleted)
				>> bits(my.t.usage_count)
				>> bits(my.t.dt_confirmed);

            return (in);
        }

        uint32_t data_size = 0;
        std::string data_sha0;
        std::string summary_sha;

		bool 		confirmed 	= false;
		bool 		deleted 	= false;	// marked for deleted
		uint32_t 	usage_count = 0;
		std::string dt_confirmed = "";
    };

	[[maybe_unused]] static void history_key_to_public(const history_key& kin, history_key_public& kout)
	{
		kout.data_size = kin.data_size;
		kout.data_sha0 = kin.data_sha[0];

		std::string t = kin.data_sha[0]+kin.data_sha[1]+kin.data_sha[2];
		SHA256 sha;
		sha.update(reinterpret_cast<const uint8_t*> (t.data()),t.size());
		uint8_t* digest = sha.digest();
		std::string checksum = SHA256::toString(digest);
		delete[] digest;

		kout.summary_sha = checksum;
	}

    [[maybe_unused]] static  bool find_history_key_by_sha_in_map(	const std::string& key_sha, const std::map<uint32_t, 
																	history_key>& map_histo, uint32_t& seq, history_key& kout)
	{
		bool found = false;
		for(auto& [seqkey, k] : map_histo)
		{
			if (k.data_sha[0] == key_sha)
			{
				found = true;
				seq = seqkey;
				kout = k;
				break;
			}
		}
		return found;
	}

	[[maybe_unused]] static void show_history_key(const std::string& local_histo_db)
	{
		if (file_util::fileexists(local_histo_db) == true)
		{
			std::map<uint32_t, history_key> map_histo;

			std::ifstream infile;
			infile.open (local_histo_db, std::ios_base::in);
			infile >> bits(map_histo);
			infile.close();

			for(auto& [seqkey, k] : map_histo)
			{
                std::string c = k.confirmed?std::string("Y"):std::string("N");
				std::cout   << "[h]" << seqkey
                            << " confirmed:" << c
                            << " confirmed dt:" << k.dt_confirmed
                            << " sha[0]:" << k.data_sha[0]
                            << " dt:" << k.dt
                            << " datasize:" << k.data_size
							<< " usage_count:" << k.usage_count
							<< std::endl;
			}
		}
	}

	[[maybe_unused]] static bool export_public_history_key(const std::string& fileHistoPrivateDB, const std::string& fileHistoPublicDB)
	{
        bool r = true;
        std::map<std::string, history_key_public> map_histo_pub;
		std::map<uint32_t, history_key> map_histo;

		if (file_util::fileexists(fileHistoPrivateDB) == true)
		{
			std::ifstream infile;
			infile.open (fileHistoPrivateDB, std::ios_base::in);
			infile >> bits(map_histo);
			infile.close();

			for(auto& [seqkey, k] : map_histo)
			{
				history_key_public kout;
				history_key_to_public(k, kout);
				map_histo_pub[k.data_sha[0]]=kout;
			}

			std::ofstream outstream;
            outstream.open(fileHistoPublicDB, std::ios_base::out);
			outstream << bits(map_histo_pub);
			outstream.close();
		}
		else
		{
            r = false;
		}
		return r;
	}

	[[maybe_unused]] static bool confirm_history_key(const std::string& local_histo_db, const std::string& local_histo_public_db, uint32_t& cnt, uint32_t& n)
	{
		cnt = 0;
		n=0;
		bool r = true;
		std::map<std::string, history_key_public> map_histo_pub;
		std::map<uint32_t, history_key> map_histo;

		if (file_util::fileexists(local_histo_public_db) == true)
		{
			std::ifstream infile;
			infile.open (local_histo_public_db, std::ios_base::in);
			infile >> bits(map_histo_pub);
			infile.close();


			if (file_util::fileexists(local_histo_db) == true)
			{
				std::ifstream infile;
				infile.open (local_histo_db, std::ios_base::in);
				infile >> bits(map_histo);
				infile.close();

                // backup
                if (file_util::fileexists(local_histo_db) == true)
                {
                    std::ofstream outfile;
                    outfile.open(local_histo_db + ".bck", std::ios_base::out);
                    outfile << bits(map_histo);
                    outfile.close();
                }


				bool update = false;
				for(auto& [shakey, kpub] : map_histo_pub)
				{
                    n++;
					history_key kpriv;
					uint32_t seq;
					bool b = find_history_key_by_sha_in_map(kpub.data_sha0, map_histo, seq, kpriv);
					if (b)
					{
						if (kpriv.confirmed == false)
						{
							kpriv.update_confirmed(true);
							map_histo[seq] = kpriv;
							update = true;
							cnt++;
						}
					}
				}

				if (update)
				{
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
				r = false;
			}
		}
		else
		{
            r = false;
		}

		return r;
	}
	
}
#endif
