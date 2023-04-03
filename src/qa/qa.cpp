#include "../../src/crypto_const.hpp"
#include "../../src/crypto_parsing.hpp"
#include "menu/menu.h"

std::string VERSION = "v0.4";
std::string FULLVERSION = VERSION + "_" + cryptoAL::parsing::get_current_date();

void qa_menu()
{
	// NEW MENU
	ns_menu::main_menu mm(FULLVERSION);
	mm.run();
}


int main()
{
    qa_menu();
    return 0;
}
