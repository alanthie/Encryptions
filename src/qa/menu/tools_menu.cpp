#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "../../../src/c_plus_plus_serializer.h"
#include "menu.h"

namespace ns_menu
{
	int main_menu::fTOOLS(int choice)
   	{
        int r = 0;
        if (choice == 1)
        {
            std::cout << "HEX(file, position, keysize)" << std::endl;
            std::cout << "Enter filename: ";
            std::string sfile;
            std::cin >> sfile;

            std::cout << "Enter position: ";
            std::string spos;
            std::cin >> spos;
            long long pos = cryptoAL::parsing::str_to_ll(spos);

            std::cout << "Enter keysize: ";
            std::string skeysize;
            std::cin >> skeysize;
            long long keysize = cryptoAL::parsing::str_to_ll(skeysize);

            std::string rr = file_util::HEX(sfile, pos, keysize);
            std::cout << "HEX(" << sfile << "," << pos << "," << keysize << ") = " << rr << std::endl;
            std::cout << std::endl;
        }
        else if (choice == 2)
        {
            std::cout << "Enter filename: ";
            std::string sfile;
            std::cin >> sfile;

            std::string rr = file_util::file_checksum(sfile);
            std::cout << "SHA(" << sfile << ") = " << rr << std::endl;
            std::cout << std::endl;
        }
        return r;
	}
}

