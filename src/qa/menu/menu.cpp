//#include "crypto_const.hpp"
#include "menu.h"
#include "rsa_menu.h"

namespace ns_menu
{

	std::optional<std::string> menu_getline(std::istream& is, const std::string& def)
	{
		for (auto no = is.rdbuf()->in_avail(); no && is && std::isspace(is.peek()); is.ignore(), --no);
		std::string ln;
		return std::getline(is, ln) ? (ln.empty() && !def.empty() ? def : ln) : (is.clear(), std::optional<std::string> {});
	}

	auto menu_getline(const std::string& prm, const std::string& def)
	{
		std::optional<std::string> o;
		do {
			std::cout << prm;
			if (!def.empty())
				std::cout << " [" << def << "]";

			std::cout << " :";
			o = menu_getline(std::cin, def);
		} while (!o.has_value() && (std::cout << "Invalid input" << std::endl));
		return *o;
	}

	std::optional<char> getchr(std::istream& is, char def, bool wholeline)
	{
		if (wholeline)
		{
			if (auto o = menu_getline(is); o.has_value())
				return (o->empty() && def ? def : ((o->size() == 1) ? o->front() : std::optional<char> {}));
			else
				return {};
		}
		return getdata<char>(is);
	}

	auto getchr(const std::string& prm, const std::string& valid, char def, bool wholeline)
	{
		const auto showopt = [&valid, def]() {
			std::cout << " (";
			for (size_t i = 0, s = valid.size(); i < s; ++i)
				std::cout << (i ? "/" : "") << valid[i];
			if (std::cout << ")"; def)
				std::cout << " [" << def << "]";
		};

		std::optional<char> o;

		do {
			if (std::cout << prm; !valid.empty())
				showopt();

			std::cout << " :";
			o = getchr(std::cin, def, wholeline);
		} while ((!o.has_value() || ((!valid.empty()) && (valid.find(*o) == std::string::npos))) && (std::cout << "Invalid input" << std::endl));

		return *o;
	}


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

	//---------------------------------------------------------------------------
	//Params = std::vector<std::variant<size_t, int, double, char, std::string>>;
	//---------------------------------------------------------------------------
	void f1(std::any& param)
	{
		auto& v = std::any_cast<Params&>(param);
		v.push_back(getnum<size_t>("Enter a pos integer"));
	}

	void f2(std::any& param)
	{
		auto& v = std::any_cast<Params&>(param);
		v.push_back(getnum<double>("Enter a real"));
	}

	void f6(std::any& param)
	{
		auto& v = std::any_cast<Params&>(param);
		v.push_back(getnum<double>("Enter a real between", 5.5, 50.5));
	}

	void f3(std::any& param)
	{
		auto& v = std::any_cast<Params&>(param);
		v.push_back(getchr("Enter a char"));
	}

	void f7(std::any& param)
	{
		auto& v = std::any_cast<Params&>(param);
		v.push_back(getchr("Enter a vowel", "aeiou", 'a'));

	}
	void f4(std::any& param)
	{
		auto& v = std::any_cast<Params&>(param);
		v.push_back(menu_getline("Enter text"));
	}

	//---------------------------------------------------------------------------
	//Params = std::vector<std::variant<size_t, int, double, char, std::string>>;
	//---------------------------------------------------------------------------
	void f51(std::any& param)
	{
		const static auto proc = [](const auto& val) {std::cout << val << std::endl; };
		auto& v = std::any_cast<Params&>(param);

		std::cout << "Entered data is\n";
		for (const auto& d : v)
			std::visit(proc, d);
	}


	void fmenu(std::any& param)
	{
		std::cout << "fmenu" << std::endl;
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
		mCFG.set_id(1);

		Menu mPuzzle
		{
			"Puzzle",
			{
				{"Make random puzzle from shared binary (like USB keys) data", 	fmenu},
				{"Resolve puzzle", 	fmenu},
			}
		};
		mPuzzle.set_main_menu(this);
		mPuzzle.set_id(2);

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
		mRSA.set_id(3);

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
		mECC.set_id(4);

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
		mECCKey.set_id(5);


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
		mHH.set_id(6);

		Menu m1 {"QA",
					{
						{"Puzzle",      &mPuzzle},
						{"Config",      &mCFG},
						{"RSA Key",     &mRSA},
						{"ECC Domain",  &mECC},
						{"ECC Key",     &mECCKey},
						{"Historical Hashes",     &mHH}
					}
				};
		m1.set_main_menu(this);
		m1.set_id(0);

		std::any param = Params {};

		m1.menu(param);
		return 0;
	}

	    void main_menu::calledby(const Menu& m, size_t option)
        {
            std::cout << "called by menu [" << m.title() << "] id " << m.id << " option " << option  << " sub menu: " << m.mitems[option].name << std::endl;

			if ((m.id == 0) && (option==2))
			{
                //RSA entry
			}
			if ((m.id == 3) && (option==0))
			{
                fRSA_1();
			}
        }
}

