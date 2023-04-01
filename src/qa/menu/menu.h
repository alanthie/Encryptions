#ifndef QA_MENU_HPP_H_INCLUDED
#define QA_MENU_HPP_H_INCLUDED

#include "../../crypto_cfg.hpp"
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
    using f_type = void(*)(std::any& param);
    class Menu;

	enum MENU_ID
	{
        ROOT = 0,
		CFG = 1,
		Puzzle,
		RSA,
		ECC_DOMAIN,
		ECC_KEY,
		HH
	};


    struct menu_item
    {
        std::string name;
        std::variant<f_type, Menu*> func;
    };
    using vmi = std::vector<menu_item>;


    class main_menu
    {
    public:
        main_menu(cryptoAL::crypto_cfg& acfg, std::string aFULLVERSION, std::string acfg_file) : cfg(acfg), FULLVERSION(aFULLVERSION), cfg_file(acfg_file) {}
        int run();

        bool                    cfg_parse_result = false;
        cryptoAL::crypto_cfg&   cfg;
        std::string             FULLVERSION;
        std::string             cfg_file;

        void calledby(const Menu& m, size_t option);

        void fRSA_1();
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

        void menu(std::any& param);

        bool erase(size_t indx);
        bool append(const menu_item& mi);
        bool insert(size_t indx, const menu_item& mi);

    private:
        class RunVisitor
        {
        public:
            RunVisitor(std::any& par) : param(par) {}

            void operator()(f_type func) { func(param); }
            void operator()(Menu* menu) { Menu::menu(*menu, param); }

        private:
            std::any& param;
        };

        static void menu(const Menu& m, std::any& param)
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

                        if (mu.p_main_menu->cfg_parse_result == false)
                            oss << "Not using a configuration file" << "\n";
                        else
                            oss<< "Current configuration file: [" << mu.p_main_menu->cfg_file << "]" << "\n";

                        oss<< "Select a task: " << "\n";
                    }
                }
                else
                {
                    oss << mu.title() << "\n";
                }

                oss << "====================================" << "\n";

                for (size_t i = 0U; i < nom; ++i)
                {
                    oss << "[" << i + 1 << "] " << mu.mitems[i].name << '\n';
                }

                oss << "[0] Exit menu\n\nEnter menu choice";
                return getnum<size_t>(oss.str(), 0, nom);
            };


            for (size_t opt = 0U; (opt = show(m)) > 0; )
            {
                if (m.p_main_menu!=nullptr)
                    m.p_main_menu->calledby(m, opt - 1);

                // R visit(Visitor&&, Variants&&...);
                // std::invoke(std::forward<Visitor>(vis), std::get<is>(std::forward<Variants>(vars))...)
                std::visit(RunVisitor(param), m.mitems[opt - 1].func);
              }
        }
    };


}
#endif
