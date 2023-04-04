#include "../../../src/uint_util.hpp"
#include "../../../src/crypto_const.hpp"
#include "../../../src/file_util.hpp"
#include "../../../src/crypto_cfg.hpp"
#include "../../../src/crypto_parsing.hpp"
#include "menu.h"

namespace ns_menu
{
	int main_menu::fCFG(int choice)
   	{
		int r = 0;

        //[1] Use a configuration file for default parameters
        //[2] Show configuration
        if (choice == 1)
        {
			this->config_first_time = false;

			std::cout << "Enter full path of the config file (0 = ./cfg.ini, 1 = skip): ";
			std::string sfile;
			sfile = get_input_string();
			if (sfile.size() == 0)
			{
			}
			else
			{
				if (sfile == "1")
				{
					//continue;
				}
                else
                {
                    if (sfile == "0") sfile = "./cfg.ini";
                    if (file_util::fileexists(sfile) == true)
                    {
                        this->cfg_file = sfile;
                        this->cfg.reset_cfg(this->cfg_file);
                        this->cfg_parse_result = this->cfg.parse();

                        if (this->cfg_parse_result)
                        {
                        }
                        else
                        {
                        }
                    }
					else
					{
						std::cerr << "no file: "  << sfile << std:: endl;
						r = -1;
					}
				}
			}
        }

        else if (choice == 2)
        {
			if (this->cfg_parse_result)
			{
				cfg.show();
			}
        }

        return r;
    }
}

