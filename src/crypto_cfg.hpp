#ifndef CRYPTO_CFG_HPP
#define CRYPTO_CFG_HPP

#include "crypto_const.hpp"
#include "ini_parser.hpp"
#include "crypto_strutil.hpp"
#include "data.hpp"
#include <iostream>

namespace cryptoAL
{
const std::string CFG_var_section  		= "var";
const std::string CFG_cmdparam_section  = "cmdparam";
const std::string CFG_keymgr_section    = "keymgr";
const std::string CFG_keygen_section    = "keygen";

// *.ini file
// [var]
// var_folder_me_jo = ~/myfolder/test/me_and_jo/
//
// [cmdparam]
// folder_my_private_rsa = [var_folder_me_jo]me/
//
// [keymgr]
// max_usage1	= keytype:rsa,bits:64,max_usage_count:1
// max_usage2	= keytype:rsa,bits:1024,max_usage_count:16
//
// [keygen]
// policy1 		= keytype:rsa, pool_first:10, pool_random:30, pool_last:10, pool_new:20, pool_max:100
//

// [cmdparam]
struct cfg_cmdparam
{
	// empty means no default provided here, default can also be override on the cmd line
	std::string filename_urls;
    std::string filename_msg_data;
    std::string filename_puzzle;
    std::string filename_partial_puzzle;
    std::string filename_full_puzzle;
    std::string filename_encrypted_data;
	std::string filename_decrypted_data;

    std::string folder_staging;
    std::string folder_local;
    std::string folder_my_private_rsa;
	std::string folder_other_public_rsa;
    std::string folder_my_private_ecc;
    std::string folder_other_public_ecc;
    std::string folder_my_private_hh;
    std::string folder_other_public_hh;

    std::string keeping;
    std::string encryped_ftp_user;
    std::string encryped_ftp_pwd;
    std::string known_ftp_server;

	std::string use_gmp;
	std::string self_test;
	std::string key_size_factor;
	std::string shufflePerc;
	std::string auto_flag;
	std::string verbose;
};

class crypto_cfg
{
public:
	crypto_cfg(const std::string& inifile, bool verb=false)
    : 	filecfg(inifile),
		verbose(verb),
		ini(inifile)
    {
    }

	void reset_cfg(const std::string& file)
	{
		// reentry allowed?
		filecfg = file;
		ini.reset(file);
		map_sections.clear();
		map_var.clear();
	}

    ~crypto_cfg() {}

	std::string filecfg;
	bool        verbose;
	ini_parser  ini;

	std::map<std::string, std::map<std::string, std::string>> map_sections;
	cfg_cmdparam cmdparam;
	std::map<std::string,std::string> map_var;

	long long get_positive_value_negative_if_invalid(const std::string& s)
	{
        if (s.size() == 0) return -1;
        return strutil::str_to_ll(s);
	}

    bool parse()
	{
		map_sections.clear();
		map_var.clear();

		bool r = true;
		if (filecfg.size() == 0)
		{
			return true;
		}

	    if (fileexists(filecfg) == false)
		{
			std::cout << "ERROR config file not found:" << filecfg << std::endl;
			return false;
		}

		map_sections = ini.get_sections();

		if (verbose)
		{
			if (verbose) std::cout << "-------------------------------------- "<< std::endl;
			std::cout << "config file content " << filecfg << std::endl;
			if (verbose) std::cout << "-------------------------------------- "<< std::endl;
			for(auto& [s, m] : map_sections)
			{
				std::cout << "[" << s << "]" << std::endl;
				for(auto& [p, v] : m)
				{
					std::cout  << p << "=" << v << std::endl;
				}
			}
			if (verbose) std::cout << "-------------------------------------- "<< std::endl;
			std::cout << std::endl;
		}

		read_var();
		read_cmdparam();

		return r;
	}

	void read_var()
	{
		if (map_sections.find(CFG_var_section) != map_sections.end())
		{
			for(auto& [svar, sval] : map_sections[CFG_var_section])
			{
				map_var[svar] = sval;
			}
		}
	}

	std::string apply_var(const std::string& s)
	{
		// var substitution of s if contain any <varname> in map_sections[CFG_var_section]
		if (s.size()==0) return s;
		std::string r = s;
		std::string token;
		std::string token_no_delimeter;

		unsigned first_delim_pos;
		unsigned last_delim_pos;
		unsigned end_pos_of_first_delim;

		while (true)
		{
			token = strutil::get_str_between_two_str(r, std::string("<"), std::string(">"), first_delim_pos, last_delim_pos, end_pos_of_first_delim);
			if (token.size() == 0) break;
			token_no_delimeter = token.substr(end_pos_of_first_delim, token.size() - (std::string("<").size() +  std::string(">").size()));

			for(auto& [svar, sval] : map_var)
			{
				if (token_no_delimeter == svar)
				{
					r.replace(first_delim_pos, std::string("<").size() +  std::string(">").size() + svar.size(), sval);
				}
				else
				{
					break;
				}
			}
		}
		return r;
	}

  	void read_cmdparam()
	{
	    if (map_sections.find(CFG_cmdparam_section) == map_sections.end())
		{
			std::cerr << "WARNING no cmdparam section in config file: " << filecfg << std::endl;
			return;
		}

	    cmdparam.filename_urls    				= apply_var(ini.get_string("filename_urls", CFG_cmdparam_section));
        cmdparam.filename_msg_data   			= apply_var(ini.get_string("filename_msg_data", CFG_cmdparam_section));

        cmdparam.filename_puzzle				= apply_var(ini.get_string("filename_puzzle", CFG_cmdparam_section));
        cmdparam.filename_full_puzzle   		= apply_var(ini.get_string("filename_full_puzzle", CFG_cmdparam_section));

        cmdparam.filename_encrypted_data      	= apply_var(ini.get_string("filename_encrypted_data", CFG_cmdparam_section));
		cmdparam.filename_decrypted_data      	= apply_var(ini.get_string("filename_decrypted_data", CFG_cmdparam_section));

        cmdparam.folder_staging            		= apply_var(ini.get_string("folder_staging", CFG_cmdparam_section));
		cmdparam.keeping        				= apply_var(ini.get_string("keeping", CFG_cmdparam_section));

        cmdparam.folder_local            		= apply_var(ini.get_string("folder_local", CFG_cmdparam_section));

		cmdparam.folder_my_private_rsa        	= apply_var(ini.get_string("folder_my_private_rsa", CFG_cmdparam_section));
		cmdparam.folder_other_public_rsa       	= apply_var(ini.get_string("folder_other_public_rsa", CFG_cmdparam_section));
		cmdparam.folder_my_private_ecc         	= apply_var(ini.get_string("folder_my_private_ecc", CFG_cmdparam_section));
		cmdparam.folder_other_public_ecc       	= apply_var(ini.get_string("folder_other_public_ecc", CFG_cmdparam_section));
		cmdparam.folder_my_private_hh           = apply_var(ini.get_string("folder_my_private_hh", CFG_cmdparam_section));
		cmdparam.folder_other_public_hh        	= apply_var(ini.get_string("folder_other_public_hh", CFG_cmdparam_section));

        cmdparam.encryped_ftp_user 				= apply_var(ini.get_string("encryped_ftp_user", CFG_cmdparam_section));
        cmdparam.encryped_ftp_pwd  				= apply_var(ini.get_string("encryped_ftp_pwd", CFG_cmdparam_section));
        cmdparam.known_ftp_server  				= apply_var(ini.get_string("known_ftp_server", CFG_cmdparam_section));

        cmdparam.use_gmp        				= apply_var(ini.get_string("use_gmp", CFG_cmdparam_section));
		cmdparam.self_test        				= apply_var(ini.get_string("self_test", CFG_cmdparam_section));
		cmdparam.key_size_factor        		= apply_var(ini.get_string("key_size_factor", CFG_cmdparam_section));
		cmdparam.shufflePerc        			= apply_var(ini.get_string("shufflePerc", CFG_cmdparam_section));
		cmdparam.auto_flag       			    = apply_var(ini.get_string("auto_flag", CFG_cmdparam_section));
	}

	void show()
	{
		std::cout << "-------------------------------------------------" << std::endl;
		std::cout << "cmd parameters section:" << std::endl;
		std::cout << "-------------------------------------------------" << std::endl;
        std::cout << "filename_urls:           " << cmdparam.filename_urls  << std::endl;
        std::cout << "filename_msg_data:       " << cmdparam.filename_msg_data << std::endl;
        std::cout << "filename_puzzle:         " << cmdparam.filename_puzzle << std::endl;
        std::cout << "filename_full_puzzle:    " << cmdparam.filename_full_puzzle  << std::endl;
        std::cout << "filename_encrypted_data: " << cmdparam.filename_encrypted_data  << std::endl;
		std::cout << "filename_decrypted_data: " << cmdparam.filename_decrypted_data  << std::endl;

        std::cout << "folder_staging:          " << cmdparam.folder_staging  << std::endl;
        std::cout << "folder_my_private_rsa:   " << cmdparam.folder_my_private_rsa << std::endl;
        std::cout << "folder_other_public_rsa: " << cmdparam.folder_other_public_rsa   << std::endl;
        std::cout << "folder_my_private_ecc:   " << cmdparam.folder_my_private_ecc   << std::endl;
        std::cout << "folder_other_public_ecc: " << cmdparam.folder_other_public_ecc << std::endl;
        std::cout << "folder_my_private_hh:    " << cmdparam.folder_my_private_hh << std::endl;
        std::cout << "folder_other_public_hh:  " << cmdparam.folder_other_public_hh << std::endl;

        std::cout << "keeping:     " << cmdparam.keeping << std::endl;
        std::cout << "use_gmp:     " << cmdparam.use_gmp << std::endl;
        std::cout << "self_test:   " << cmdparam.self_test << std::endl;
        std::cout << "auto_flag:   " << cmdparam.auto_flag << std::endl;
        std::cout << "shufflePerc: " << cmdparam.shufflePerc << std::endl;
        std::cout << "key_size_factor: " << cmdparam.key_size_factor << std::endl;
		std::cout << "-------------------------------------------------" << std::endl<< std::endl;
	}


};



} //namespace
#endif // CRYPTO_CFG_HPP
