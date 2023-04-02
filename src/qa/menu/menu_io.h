#ifndef QA_MENU_IO_HPP_H_INCLUDED
#define QA_MENU_IO_HPP_H_INCLUDED

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
    std::string trim(const std::string& s);

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
        if (wholeline) 
        {
            const auto o = menu_getline(is);
            if (!o.has_value())
			{
				std::cout << "const auto o = menu_getline(is); return no value" << std::endl;
			}
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
        } 
        while ( (!o.has_value() || (((*o < nmin) || (*o > nmax)))) 
                && (std::cout << "Invalid input" << std::endl) );

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

}
#endif
