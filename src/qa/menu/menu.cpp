//
#include "menu.h"

namespace ns_menu
{
	Menu::Menu() {}
	Menu::Menu(const std::string& t, const vmi& vm) : stitle(t), mitems(vm) {}

	std::string Menu::title() const noexcept
	{
		return stitle;
	}
	void Menu::title(const std::string& t)
	{
		stitle = t;
	}

	void Menu::menu()
	{
		menu(*this);
	}

	bool Menu::erase(size_t indx)
	{
		if (indx < mitems.size()) {
			mitems.erase(mitems.begin() + indx);
			return true;
		}
		return false;
	}
	bool Menu::append(const menu_item& mi)
	{
		mitems.emplace_back(mi);
		return true;
	}
	bool Menu::insert(size_t indx, const menu_item& mi)
	{
		if (indx < mitems.size()) {
			mitems.insert(mitems.begin() + indx, mi);
			return true;
		}

		return false;
	}

	int main_menu::run()
	{
		Menu mCFG
		{
			"Config",
			{
				{"Use a configuration file for default parameters", 1}, // The variant_val is a int
				{"Show configuration", 	2},
			}
		};
		mCFG.set_main_menu(this);
		mCFG.set_id(MENU_ID::CFG);

		Menu mPuzzle
		{
			"Puzzle",
			{
				{"Make random puzzle from shared binary (like USB keys) data",	1},
				{"Resolve puzzle", 	2},
			}
		};
		mPuzzle.set_main_menu(this);
		mPuzzle.set_id(MENU_ID::Puzzle);

		Menu mRSA
		{
			"RSA Key",
			{
				{"View my private RSA key", 	1},
				{"View my public RSA key (also included in the private db)", 2},
				{"View other public RSA key", 	3},
				{"Export my public RSA key", 	4},
				{"Generate RSA key with OPENSSL command line (fastest)", 5},
				{"Test RSA GMP key generator", 6},
				{"Generate RSA key with GMP (fast)", 7}
			}
		};
		mRSA.set_main_menu(this);
		mRSA.set_id(MENU_ID::RSA);

		Menu mECC
		{
			"ECC Domain",
			{
				{"Import an elliptic curve domain generated from ecgen (output manually saved in a file)", 	1},
				{"Generate an elliptic curve domain with ecgen",2},
				{"View my elliptic curve domains", 3},
				{"Import the elliptic curve domains of other", 4},
				{"Elliptic Curve test with GMP", 5}
			}
		};
		mECC.set_main_menu(this);
		mECC.set_id(MENU_ID::ECC_DOMAIN);

		Menu mECCKey
		{
			"ECC Key",
			{
				{"Generate an elliptic curve key", 	1},
				{"View my private elliptic curve keys",2},
				{"Export my public elliptic curve keys", 3},
				{"View my public elliptic curve keys (also included in the private db)", 4},
				{"View other public elliptic curve keys", 5},
			}
		};
		mECCKey.set_main_menu(this);
		mECCKey.set_id(MENU_ID::ECC_KEY);


		Menu mHH
		{
			"Historical Hashes",
			{
				{"View my private encode history hashes", 	1},
				{"View my public decode history hashes",2},
				{"Export public decode history hashes for confirmation", 3},
				{"Confirm other public decode history hashes", 4},
			}
		};
		mHH.set_main_menu(this);
		mHH.set_id(MENU_ID::HH);

		Menu mWBAES
		{
			"Whitebox AES keys",
			{
				{"Create one or multiple WB AES key", 	1},
				{"Create one or multiple WB AES key from one or multiple instruction files", 2}
			}
		};
		mWBAES.set_main_menu(this);
		mWBAES.set_id(MENU_ID::WBAES);

		Menu mTOOLS
		{
			"Tools",
			{
				{"HEX file dump", 	1},
				{"SHA256 of a file",2},
				{"Hardware info",3}
			}
		};
		mTOOLS.set_main_menu(this);
		mTOOLS.set_id(MENU_ID::TOOLS);

		Menu m1 {"QA",
					{
						{"Config",      &mCFG}, // The variant_val is a menu
						{"Puzzle",      &mPuzzle},
						{"RSA Key",     &mRSA},
						{"ECC Domain",  &mECC},
						{"ECC Key",     &mECCKey},
						{"Historical Hashes", &mHH},
						{"Whitebox AES keys", &mWBAES},
						{"Tools", &mTOOLS}
					}
				};
		m1.set_main_menu(this);
		m1.set_id(MENU_ID::ROOT);

		m1.menu();
		return 0;
	}

    void main_menu::calledby(const Menu& m, size_t option)
    {
        //std::cout << "called by menu [" << m.title() << "] id " << m.id << " option " << option  << " sub menu: " << m.mitems[option].name << std::endl;

        if ((m.id == MENU_ID::ROOT) && (option==2))
        {
            //RSA entry
        }
        else if (m.id == MENU_ID::CFG)
        {
            fCFG(option+1);
        }
		else if (m.id == MENU_ID::RSA)
        {
            fRSA(option+1);
        }
		else if (m.id == MENU_ID::ECC_DOMAIN)
        {
            fECCDomain(option+1);
        }
		else if (m.id == MENU_ID::ECC_KEY)
        {
            fECCKey(option+1);
        }
		else if (m.id == MENU_ID::HH)
        {
            fHH(option+1);
        }
		else if (m.id == MENU_ID::Puzzle)
        {
            fPuzzle(option+1);
        }
		else if (m.id == MENU_ID::WBAES)
        {
            fWBAES(option+1);
        }
		else if (m.id == MENU_ID::TOOLS)
        {
            fTOOLS(option+1);
        }
    }
}

