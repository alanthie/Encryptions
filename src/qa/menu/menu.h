#ifndef QA_MENU_HPP_H_INCLUDED
#define QA_MENU_HPP_H_INCLUDED

#include "../../crypto_cfg.hpp"

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

    using Params = std::vector<std::variant<size_t, int, double, char, std::string>>;

    // Removes leading and trailing white-space chars from string s
    // s - string to use (not changed)
    // returns updated string
    inline std::string trim(const std::string& s)
    {
        constexpr char whitespace[] = " \t\n\r";
        const size_t first = s.find_first_not_of(whitespace);
        return (first != std::string::npos) ? s.substr(first, (s.find_last_not_of(whitespace) - first + 1)) : std::string {};
    }


    // Converts a text number to specified type. All of the text must be a valid number of the specified type. eg 63q is invalid
    // Defaults to type int
    // st - string to convert
    // returns either value of converted number or no value if text number cannot be converted
    template<typename T = int>
    bool startsWithDigit(const std::string& s)
    {
        if (s.empty())
            return false;

        if (std::isdigit(s.front()))
            return true;

        return (((std::is_signed<T>::value && (s.front() == '-')) || (s.front() == '+'))
                    && ((s.size() > 1) && std::isdigit(s[1])));
    }

    template<typename T = int>
    std::optional<T> stonum(const std::string& st)
    {
        const auto s = trim(st);
        //bool ok = s.empty() ? false : (std::isdigit(s.front()) || (((std::is_signed<T>::value && (s.front() == '-')) || (s.front() == '+')) && ((s.size() > 1) && std::isdigit(s[1]))));
        bool ok = startsWithDigit<T>(s);

        auto v = T {};

        if (ok) {
            std::istringstream ss(s);

            ss >> v;
            ok = (ss.peek() == EOF);
        }

        return ok ? v : std::optional<T> {};
    }


    // Obtain a line of text from specified stream. Removes any existing data from input buffer
    // is - input stream
    // def - optional default text if no text entered
    // returns either valid input line or no value if problem obtaining input
    std::optional<std::string> menu_getline(std::istream& is, const std::string& def = "");


    // Obtain a line of text from console. First displays prompt text. If default text provided display within [..] after prompt
    // prm - optional prompt text to display first
    // def - optional default text if no text entered
    // returns entered text as type string. No error conditions. Only returns when valid data entered
    auto menu_getline(const std::string& prm = "", const std::string& def = "");


    // Extract next item of data from specified stream. Data must terminate with a white-space char
    // Defaults to type string. Note extraction for string stops at white-space char
    // is - stream from which to extract data
    // returns either valid extracted data or no value if problem extracting data
    template<typename T = std::string>
    std::optional<T> getdata(std::istream& is)
    {
        auto i = T {};
        const bool b = (is >> i) && std::isspace(is.peek());

        for (is.clear(); is && !std::isspace(is.peek()); is.ignore());
        return b ? i : std::optional<T> {};
    }


    // Obtains a number from specified stream in specified type
    // Default of number type is int
    // is - stream from which to obtain number
    // wholeline - true if only one number per line (default), false if can have multiple numbers per line.
    // returns either valid number of required type or no value if problem extracting data
    template<typename T = int>
    auto getnum(std::istream& is, bool wholeline = true)
    {
        if (wholeline) {
            const auto o = menu_getline(is);
            return o.has_value() ? stonum<T>(*o) : std::optional<T> {};
        }

        return getdata<T>(is);
    }


    // Obtains a number from the console. First displays prompt text
    // If specified, number must be within the specified min..max range and range displayed as (...) after prm
    // prm - optional prompt text to display first
    // nmin - optional minimum valid value
    // nmax - optional maximum valid value
    // wholeline - true if only one number per line (default), false if can have multiple numbers per line
    // returns valid number of required type. No error conditions. Only returns when valid number entered
    template <typename T = int>
    auto getnum(const std::string& prm = "", T nmin = std::numeric_limits<T>::lowest(), T nmax = std::numeric_limits<T>::max(), bool wholeline = true)
    {
        const auto showdefs = [nmin, nmax]() {
            std::cout << " (";

            if (nmin != std::numeric_limits<T>::lowest() || std::is_unsigned<T>::value)
                std::cout << nmin;

            std::cout << " - ";

            if (nmax != std::numeric_limits<T>::max())
                std::cout << nmax;

            std::cout << ")";
        };

        std::optional<T> o;

        do {
            std::cout << prm;

            if ((nmin != std::numeric_limits<T>::lowest()) || (nmax != std::numeric_limits<T>::max()))
                showdefs();

            std::cout << " :";
            o = getnum<T>(std::cin, wholeline);
        } while ((!o.has_value() || (((*o < nmin) || (*o > nmax)))) && (std::cout << "Invalid input" << std::endl));

        return *o;
    }


    // Obtains a char from the specified stream
    // is - stream from which to obtain number
    // def - default char to return if no character obtained
    // wholeline - true if only one char per line (default), false if can have multiple chars per line
    // returns either valid character or no value if problem extracting data
    std::optional<char> getchr(std::istream& is, char def = 0, bool wholeline = true);

    // Obtains a char from the console. First displays prompt text
    // prm - optional prompt text to display first
    // valid - optional string containing valid values for the char. Displayed within (...)
    // def - optional default char to use if none entered. Displayed within [...]
    // wholeline - true if only one char per line (default), false if can have multiple chars per line
    // returns valid char. No error conditions. Only returns when valid char entered
    auto getchr(const std::string& prm = "", const std::string& valid = "", char def = 0, bool wholeline = true);



    using f_type = void(*)(std::any& param);
    class Menu;


    struct menu_item
    {
        std::string name;
        std::variant<f_type, Menu*> func;
    };
    using vmi = std::vector<menu_item>;

    class Menu;

    class main_menu
    {
    public:
        main_menu(cryptoAL::crypto_cfg& acfg, std::string aFULLVERSION, std::string acfg_file) : cfg(acfg), FULLVERSION(aFULLVERSION), cfg_file(acfg_file) {}
        int run();

        bool cfg_parse_result = false;
        cryptoAL::crypto_cfg& cfg;
        std::string FULLVERSION;
        std::string cfg_file;

        void calledby(const Menu& m, size_t option);

        void fRSA_1();
    };

    class Menu
    {
    public:
        main_menu* p_main_menu = nullptr;
        int id;
        std::string stitle;
        std::vector<menu_item> mitems;

        void set_main_menu(main_menu* p) { p_main_menu = p;}
        void set_id(int aid) { id = aid;}

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


    void f1(std::any& param);
    void f2(std::any& param);
    void f6(std::any& param);
    void f3(std::any& param);
    void f7(std::any& param);
    void f4(std::any& param);
    void f51(std::any& param);
    void f5(std::any& param);


}
#endif
