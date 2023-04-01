#include "../mathcommon.h"
#include "../../../src/crypto_const.hpp"
#include "../rsa_gen.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "menu.h"

namespace ns_menu
{
using namespace cryptoAL;

	bool fileexists(const std::filesystem::path& p, std::filesystem::file_status s = std::filesystem::file_status{})
	{
		if(std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists(p))
			return true;
		else
			return false;
	}

    void main_menu::fRSA_1()
    {
        // 7.  RSA Key: View my private RSA key"
        bool cfg_parse_result = this->cfg_parse_result;
        cryptoAL::crypto_cfg& cfg = this->cfg;

        std::string fileRSADB;
        if ((cfg_parse_result) && (cfg.cmdparam.folder_my_private_rsa.size()>0))
        {
            fileRSADB = cfg.cmdparam.folder_my_private_rsa + RSA_MY_PRIVATE_DB;
        }
        else
        {
            std::cout << "Enter path for my private rsa database " << RSA_MY_PRIVATE_DB << " (0 = current directory) : ";
            std::string pathdb;
            std::cin >> pathdb;
            if (pathdb == "0") pathdb = "./";
            fileRSADB = pathdb + RSA_MY_PRIVATE_DB;
        }

        std::cout << "Only show summary (0 = true): ";
        std::string osummary;
        std::cin >> osummary;
        bool onlysummary=false;
        if (osummary == "0") onlysummary = true;

        //qaclass qa;
        std::map< std::string, generate_rsa::rsa_key > map_rsa_private;

        // View
        if (fileexists(fileRSADB) == true)
        {
            std::ifstream infile;
            infile.open (fileRSADB, std::ios_base::in);
            infile >> bits(map_rsa_private);
            infile.close();

            if (onlysummary == false)
            {
                for(auto& [user, k] : map_rsa_private)
                {
                    std::cout << "key name: " << user << std:: endl;
                    std::cout << "key size: " << k.key_size_in_bits << std:: endl;
                    std::cout << "key public  n (base 10): " << k.get_n()<< std:: endl;
                    std::cout << "key public  e (base 10): " << k.get_e() << std:: endl;
                    std::cout << "key private d (base 10): " << k.get_d() << std:: endl;
                    std::cout << "key confirmed : " << k.confirmed << std::endl;
                    std::cout << "key marked for delete : " << k.deleted << std::endl;
                    std::cout << "key usage count: " << k.usage_count<< std::endl;
                    std::cout << std:: endl;
                }
            }
        }
        else
        {
            std::cerr << "no file: "  << fileRSADB << std:: endl;
            return;
        }

        std::cout << "---------------------------" << std::endl;
        std::cout << "Summary of " << fileRSADB << std::endl;
        std::cout << "---------------------------" << std::endl;
        for(auto& [user, k] : map_rsa_private)
        {
            std::cout << "[r]" << user << std:: endl;
        }
        std::cout << std:: endl;
    }

}
