#ifndef CRYPTO_KEYMGR_H_INCLUDED
#define CRYPTO_KEYMGR_H_INCLUDED

#include "base_const.hpp"
#include "crypto_const.hpp"
#include "data.hpp"
#include "crypto_file.hpp"
#include "crypto_key_parser.hpp"
#include "crc32a.hpp"
#include "c_plus_plus_serializer.h"

namespace cryptoAL
{
namespace keymgr
{
    struct public_key_desc
    {
        std::string         path_private_db;
        std::string         public_filename;
        std::string         public_other_short_filename;
        CRYPTO_FILE_TYPE    filetype;
        cryptodata*         buffer = nullptr;

        public_key_desc(const std::string& f, CRYPTO_FILE_TYPE t)
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
            else if (t == CRYPTO_FILE_TYPE::HH_PUBLIC)
            {
                public_filename = path_private_db + HHKEY_MY_PUBLIC_DECODE_DB; // reading the exported file
                public_other_short_filename = HHKEY_OTHER_PUBLIC_DECODE_DB;		// remote name
            }
        }
    };

    bool export_public_key(const std::string& path_private_db, CRYPTO_FILE_TYPE t, bool& key_exist)
    {
        bool r = true;
		key_exist = false;

        if (t == CRYPTO_FILE_TYPE::RSA_PUBLIC)
        {
            std::string filePrivateRSADB = path_private_db + RSA_MY_PRIVATE_DB;
            std::string filePublicRSADB  = path_private_db + RSA_MY_PUBLIC_DB;

			std::map< std::string, generate_rsa::rsa_key > map_rsa_private;
			std::map< std::string, generate_rsa::rsa_key > map_rsa_public;

			if (cryptoAL::fileexists(filePrivateRSADB) == true)
			{
				key_exist = true;
				std::ifstream infile;
				infile.open(filePrivateRSADB, std::ios_base::in);
				infile >> bits(map_rsa_private);
				infile.close();

				for(auto& [keyname, k] : map_rsa_private)
				{
                    generate_rsa::rsa_key key_public;
                    key_public.key_size_in_bits = k.key_size_in_bits ;
                    key_public.s_n = k.s_n ;
                    key_public.s_e = k.s_e ;
                    key_public.s_d = "" ;

                    map_rsa_public.insert(std::make_pair(keyname,  key_public));
				}

				{
					std::ofstream out;
					out.open(filePublicRSADB, std::ios_base::out);
					out << bits(map_rsa_public);
					out.close();
				}
			}
			else
			{
			  	std::cerr << "WARNING no file: " << filePrivateRSADB << std:: endl;
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
				key_exist = true;
				std::ifstream infile;
				infile.open (filePrivateECCDB, std::ios_base::in);
				infile >> bits(map_ecc_private);
				infile.close();

				for(auto& [keyname, k] : map_ecc_private)
				{
                    ecc_key key_public(k.dom, k.s_kg_x, k.s_kg_y, "");
                    map_ecc_public.insert(std::make_pair(keyname,  key_public) );
				}

				{
					std::ofstream out;
					out.open(filePublicECCDB, std::ios_base::out);
					out << bits(map_ecc_public);
					out.close();
				}
			}
			else
			{
			  	std::cerr << "WARNING no file: " << filePrivateECCDB << std:: endl;
			}
        }
        else if (t == CRYPTO_FILE_TYPE::HH_PUBLIC)
        {
            std::string filePrivateHistoDB = path_private_db + HHKEY_MY_PRIVATE_DECODE_DB;
            std::string filePublicHistoDB  = path_private_db + HHKEY_MY_PUBLIC_DECODE_DB;

			if (cryptoAL::fileexists(filePrivateHistoDB) == true)
			{
				key_exist = true;
                std::map<uint32_t, history_key> map_histo;
                std::map<std::string, history_key_public> map_histo_pub;

                std::ifstream infile;
                infile.open (filePrivateHistoDB, std::ios_base::in);
                infile >> bits(map_histo);
                infile.close();

                for(auto& [seqkey, k] : map_histo)
                {
                    history_key_public kout;
                    history_key_to_public(k, kout); // kout = SHA (kin.data_sha[0]+kin.data_sha[1]+kin.data_sha[2]);
                    map_histo_pub[k.data_sha[0]]=kout;
                }

                std::ofstream outstream;
                outstream.open(filePublicHistoDB, std::ios_base::out);
                outstream << bits(map_histo_pub);
                outstream.close();
			}
			else
			{
				std::cerr << "WARNING no file: " << filePrivateHistoDB << std:: endl;
			}
        }
        return r;
    }

	bool export_public_keys(std::vector<public_key_desc>& vout,
                            const std::string&  folder_my_private_rsa,
                            const std::string&  folder_my_private_ecc,
                            const std::string&  folder_my_private_hh)
	{
		bool key_exist[3];
        bool r = true;
        if (r) r = export_public_key(folder_my_private_rsa  , CRYPTO_FILE_TYPE::RSA_PUBLIC, key_exist[0]);
        if (r) r = export_public_key(folder_my_private_ecc  , CRYPTO_FILE_TYPE::ECC_PUBLIC, key_exist[1]);
        if (r) r = export_public_key(folder_my_private_hh   , CRYPTO_FILE_TYPE::HH_PUBLIC,  key_exist[2]);

        if (r)
        {
            if (key_exist[0]) vout.emplace_back(folder_my_private_rsa  , CRYPTO_FILE_TYPE::RSA_PUBLIC);
            if (key_exist[1]) vout.emplace_back(folder_my_private_ecc  , CRYPTO_FILE_TYPE::ECC_PUBLIC);
            if (key_exist[2]) vout.emplace_back(folder_my_private_hh   , CRYPTO_FILE_TYPE::HH_PUBLIC);
        }
        return r;
	}

	bool sortkey(const std::string& a, const std::string& b) 
	{ 
		int na = a.size() - 19; if (na < 1) na = 0;
		int nb = b.size() - 19; if (nb < 1) nb = 0;
		std::string ta = a.substr(na);
		std::string tb = b.substr(nb);
		return (ta<tb); 
	}

	bool get_n_keys(	keyspec_type t, uint32_t n, bool first, bool last, bool random, std::vector<std::string>&  vkeys_out,
						const std::string& folder_other_public_rsa,
                       	const std::string& folder_other_public_ecc,
                       	const std::string& folder_my_private_hh)
	{
		std::vector<std::string> vmapkeyname;
		
		if (t == keyspec_type::RSA)
		{
			std::string filePublicOtherDB = folder_other_public_rsa + RSA_OTHER_PUBLIC_DB;
			std::map<std::string, generate_rsa::rsa_key> map_rsa_public;
			// fileexist...
			
			std::ifstream infile;
			infile.open (filePublicOtherDB, std::ios_base::in);
			infile >> bits(map_rsa_public);
			infile.close();
				
			for(auto& [keyname, k] : map_rsa_public)
			{
				vmapkeyname.push_back(keyname);
			}
		}
		else if (t == keyspec_type::ECC)
		{
			std::string filePublicOtherDB = folder_other_public_ecc + ECCKEY_OTHER_PUBLIC_DB;
			std::map<std::string, ecc_key> map_ecc_public;
			// fileexist...
			
			std::ifstream infile;
			infile.open (filePublicOtherDB, std::ios_base::in);
			infile >> bits(map_ecc_public);
			infile.close();

			for(auto& [keyname, k] : map_ecc_public)
			{
				vmapkeyname.push_back(keyname);
			}
		}
		else if (t == keyspec_type::HH)
		{
			std::string fileMyPrivaterDB = folder_my_private_hh + HHKEY_MY_PRIVATE_ENCODE_DB;
			std::map<std::string, history_key_public> map_hh_public;
			// fileexist...
			
			std::ifstream infile;
			infile.open (fileMyPrivaterDB, std::ios_base::in);
			infile >> bits(map_hh_public);
			infile.close();
				
			for(auto& [keyname, k] : map_hh_public)
			{
				vmapkeyname.push_back(keyname);
			}
		}
		
		// TODO some ordering propery required in db or dt MY_RSAKEY_512_2023-03-18_23:32:34 in key name...
		std::sort(vmapkeyname.begin(), vmapkeyname.end(), sortkey); 

		if (first)
		{
			if (n > vmapkeyname.size()) n = vmapkeyname.size();
			for(size_t i = 0; i< n; i++)
			{
				vkeys_out.push_back(vmapkeyname[i]);
			}
		}
		else if (last)
		{
			if (n > vmapkeyname.size()) n = vmapkeyname.size();
			for(size_t i = vmapkeyname.size() - 1; i >= vmapkeyname.size() - n; i--)
			{
				vkeys_out.push_back(vmapkeyname[i]);
			}
		}
		else if (random)
		{
			if (n > vmapkeyname.size()) n = vmapkeyname.size();
			// TODO
		}
		return true;
	}
	
	bool materialize_keys(	keyspec& key_in,
							const std::string& folder_other_public_rsa,
                            const std::string& folder_other_public_ecc,
                            const std::string& folder_my_private_hh)
	{
		bool r = true;

		if (key_in.is_spec)
		{
			if (key_in.first_n > 0)
			{
				r = get_n_keys(key_in.ktype, key_in.first_n, true, false, false, key_in.vmaterialized_keyname, folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh);
			}
			if (key_in.last_n > 0)
			{
				r = get_n_keys(key_in.ktype, key_in.last_n, false, true, false, key_in.vmaterialized_keyname, folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh);
			}
			if (key_in.random_n > 0)
			{
				r = get_n_keys(key_in.ktype, key_in.random_n, false, false, true, key_in.vmaterialized_keyname, folder_other_public_rsa, folder_other_public_ecc, folder_my_private_hh);
			}
		}
 		else
 		{
		}
		
		return r;
	}

}
}
#endif
