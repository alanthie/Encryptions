//#include "crypto_const.hpp"
#include "menu_io.h"

namespace ns_menu
{
    std::string trim(const std::string& s)
    {
        constexpr char whitespace[] = " \t\n\r";
        const size_t first = s.find_first_not_of(whitespace);
        return (first != std::string::npos) ? s.substr(first, (s.find_last_not_of(whitespace) - first + 1)) : std::string {};
    }
	
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

}

