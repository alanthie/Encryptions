//
#include "menu.h"
#include "rsa_menu.h"

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

	void Menu::menu(std::any& param)
	{
		menu(*this, param);
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

	void fmenu(std::any& param)
	{
		//std::cout << "fmenu" << std::endl;
	}

	int main_menu::run()
	{
		Menu mCFG
		{
			"Config",
			{
				{"Use a configuration file for default parameters", 	fmenu},
				{"Show configuration", 	fmenu},
			}
		};
		mCFG.set_main_menu(this);
		mCFG.set_id(MENU_ID::CFG);

		Menu mPuzzle
		{
			"Puzzle",
			{
				{"Make random puzzle from shared binary (like USB keys) data", 	fmenu},
				{"Resolve puzzle", 	fmenu},
			}
		};
		mPuzzle.set_main_menu(this);
		mPuzzle.set_id(MENU_ID::Puzzle);

		Menu mRSA
		{
			"RSA Key",
			{
				{"View my private RSA key", 	fmenu},
				{"View my public RSA key (also included in the private db)", 	fmenu},
				{"View other public RSA key", 	fmenu},
				{"Export my public RSA key", 	fmenu},
				{"Generate RSA key with OPENSSL command line (fastest)", fmenu},
				{"Test RSA GMP key generator", fmenu},
				{"Generate RSA key with GMP (fast)", 	fmenu}
			}
		};
		mRSA.set_main_menu(this);
		mRSA.set_id(MENU_ID::RSA);

		Menu mECC
		{
			"ECC Domain",
			{
				{"Import an elliptic curve domain generated from ecgen (output manually saved in a file)", 	fmenu},
				{"Generate an elliptic curve domain with ecgen",fmenu},
				{"View my elliptic curve domains", fmenu},
				{"Import the elliptic curve domains of other", fmenu},
				{"Elliptic Curve test with GMP", fmenu}
			}
		};
		mECC.set_main_menu(this);
		mECC.set_id(MENU_ID::ECC_DOMAIN);

		Menu mECCKey
		{
			"ECC Key",
			{
				{"Generate an elliptic curve key", 	fmenu},
				{"View my private elliptic curve keys",fmenu},
				{"Export my public elliptic curve keys", fmenu},
				{"View my public elliptic curve keys (also included in the private db)", fmenu},
				{"View other public elliptic curve keys", fmenu},
			}
		};
		mECCKey.set_main_menu(this);
		mECCKey.set_id(MENU_ID::ECC_KEY);


		Menu mHH
		{
			"Historical Hashes",
			{
				{"View my private encode history hashes", 	fmenu},
				{"View my public decode history hashes",fmenu},
				{"Export public decode history hashes for confirmation", fmenu},
				{"Confirm other public decode history hashes", fmenu},
			}
		};
		mHH.set_main_menu(this);
		mHH.set_id(MENU_ID::HH);

		Menu m1 {"QA",
					{
						{"Config",      &mCFG},
						{"Puzzle",      &mPuzzle},
						{"RSA Key",     &mRSA},
						{"ECC Domain",  &mECC},
						{"ECC Key",     &mECCKey},
						{"Historical Hashes",     &mHH}
					}
				};
		m1.set_main_menu(this);
		m1.set_id(MENU_ID::ROOT);

		std::any param = Params {};

		m1.menu(param);
		return 0;
	}

	    void main_menu::calledby(const Menu& m, size_t option)
        {
            std::cout << "called by menu [" << m.title() << "] id " << m.id << " option " << option  << " sub menu: " << m.mitems[option].name << std::endl;

			if ((m.id == MENU_ID::ROOT) && (option==2))
			{
                //RSA entry
			}
			if ((m.id == MENU_ID::RSA) && (option==0))
			{
                fRSA_1();
			}
        }
}

