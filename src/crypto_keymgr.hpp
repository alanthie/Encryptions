#ifndef CRYPTO_KEYMGR_H_INCLUDED
#define CRYPTO_KEYMGR_H_INCLUDED

#include "base_const.hpp"
#include "crypto_const.hpp"
#include "c_plus_plus_serializer.h"
#include "data.hpp"
#include "crypto_file.hpp"
#include "crc32a.hpp"
#include <map>
#include <string>

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
                public_filename = path_private_db + HHKEY_MY_PUBLIC_ENCODE_DB;
                public_other_short_filename = HHKEY_OTHER_PUBLIC_ENCODE_DB;
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
            std::string filePrivateHistoDB = path_private_db + HHKEY_MY_PRIVATE_ENCODE_DB;
            std::string filePublicHistoDB  = path_private_db + HHKEY_MY_PUBLIC_ENCODE_DB;

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
                    history_key_to_public(k, kout);
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



}
}
#endif
