#ifndef QA_MENU_HPP_H_INCLUDED
#define QA_MENU_HPP_H_INCLUDED

#include "../../crypto_cfg.hpp"
#include "../../crypto_parsing.hpp"
#include "menu_io.h"

#include <iostream>
#include <any>
#include <string>
#include <variant>
#include <vector>
#include <type_traits>
#include <optional>
#include <sstream>
#include <limits>
#include <cctype>
#include <filesystem>

namespace ns_menu
{
    class Menu;

    static std::string get_input_string()
    {
        //std::cin stops reading as soon as it encounters a space or new lin
        std::string r;
        std::cin >> r;
        std::cin.ignore(10000, '\n');
        std::cin.clear();
        return r;
    }

	enum MENU_ID
	{
        ROOT = 0,
		CFG = 1,
		Puzzle,
		RSA,
		ECC_DOMAIN,
		ECC_KEY,
		HH,
        WBAES,
        TOOLS
	};


    struct menu_item
    {
        std::string name;
        std::variant<int, Menu*> variant_val;
    };
    using vmi = std::vector<menu_item>;


    class main_menu
    {
    public:
        main_menu(std::string version): cfg("", false), FULLVERSION(version) {}

        int run();

        bool                    cfg_parse_result = false;
        cryptoAL::crypto_cfg    cfg;
        std::string             FULLVERSION;
        std::string             cfg_file;
        bool                    config_first_time = false;

        void calledby(const Menu& m, size_t option);

        int fCFG(size_t choice);
        int fPuzzle(size_t choice);
        int fRSA(size_t choice);
        int fECCDomain(size_t choice);
        int fECCKey(size_t choice);
        int fHH(size_t choice);
        int fWBAES(size_t choice);
        int fTOOLS(size_t choice);
    };

    class Menu
    {
    public:
        main_menu*  p_main_menu = nullptr;
        MENU_ID     id;
        std::string stitle;

        std::vector<menu_item> mitems;

        void set_main_menu(main_menu* p) { p_main_menu = p;}
        void set_id(MENU_ID aid) { id = aid;}

        Menu();
        Menu(const std::string& t, const vmi& vm) ;

        std::string title() const noexcept;
        void title(const std::string& t);

        void menu();

        bool erase(size_t indx);
        bool append(const menu_item& mi);
        bool insert(size_t indx, const menu_item& mi);

    private:
        class RunVisitor
        {
        public:
            RunVisitor(const Menu& mctx) : m_ctx(mctx) {}

            void operator()([[maybe_unused]] int choice) { }
            void operator()(Menu* menu)
            {
                // next menu on stack
                Menu::menu(*menu);
            }

            const Menu& m_ctx;
        };

        static void menu(const Menu& m)
        {
            const static auto show = [](const Menu& mu)
            {
                std::ostringstream oss;
                const auto nom = mu.mitems.size();

                oss << "\n";
                oss << "====================================" << "\n";

                if (mu.id == 0)
                {
                    oss << mu.title();
                    if (mu.p_main_menu != nullptr)
                    {
                        oss  << " version: " << mu.p_main_menu->FULLVERSION   << "\n";
                    }
                }
                else
                {
                    oss << mu.title() << "\n";
                }

                if (mu.p_main_menu->cfg_parse_result == false)
                    oss << "Not using a configuration file" << "\n";
                else
                    oss<< "Current configuration file: [" << mu.p_main_menu->cfg_file << "]" << "\n";

                oss << "====================================" << "\n";

                for (size_t i = 0U; i < nom; ++i)
                {
                    oss << "[" << i + 1 << "] " << mu.mitems[i].name << '\n';
                }

                oss << "[0] Exit this menu\n\nEnter option";
                std::cout << oss.str() << " ==> " ;

                std::string schoice = get_input_string();
                long long choice = cryptoAL::parsing::str_to_ll(schoice);

                while ((choice < 0) || (choice > (long long )nom))
                {
                    std::cout << "invalid entry" << std::endl;
                    std::cout << oss.str()<< " ==> " ;

                    schoice = get_input_string();
                    choice = cryptoAL::parsing::str_to_ll(schoice);
                }
                std::cout << std::endl;
                return (int)choice;

                //return getnum<size_t>(oss.str(), 0, nom);
            };

            // SHOW new menu selected, wait menu option selection, calledby() if opt > 0
            for (size_t opt = 0U; (opt = show(m)) > 0; )
            {
                if (m.p_main_menu!=nullptr)
                    m.p_main_menu->calledby(m, opt - 1);

                // std::invoke(std::forward<Visitor>(vis), std::get<is>(std::forward<Variants>(vars))...);
                std::visit(RunVisitor(m), m.mitems[opt - 1].variant_val); // int or menu
           }

        }
    };


}
#endif
