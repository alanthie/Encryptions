#ifndef _INCLUDES_crypto_strutil_HPP
#define _INCLUDES_crypto_strutil_HPP

#include "crypto_const.hpp"
#include <sstream>
#include <iomanip>
#include <string>
#include <algorithm>

namespace cryptoAL
{
namespace strutil
{

    // trim from start (in place)
    static inline void ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
    }

    // trim from end (in place)
    static inline void rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), s.end());
    }

    // trim from both ends (in place)
    static inline void trim(std::string &s) {
        rtrim(s);
        ltrim(s);
    }

    // trim from start (copying)
    static inline std::string ltrim_copy(std::string s) {
        ltrim(s);
        return s;
    }

    // trim from end (copying)
    static inline std::string rtrim_copy(std::string s) {
        rtrim(s);
        return s;
    }

    // trim from both ends (copying)
    static inline std::string trim_copy(std::string s) {
        trim(s);
        return s;
    }

    template <class T> std::string to_string(T val)
    {
        std::stringstream ss;
        ss << val;
        return ss.str();
    }

    static int stoi(const std::string& str)
    {
        std::stringstream ss;
        int ret;
        ss << str;
        ss >> ret;
        return ret;
    }

    static long stol(const std::string& str)
    {
        std::stringstream ss;
        long ret;
        ss << str;
        ss >> ret;
        return ret;
    }

    static float stof(const std::string& str)
    {
        std::stringstream ss;
        float ret;
        ss << str;
        ss >> ret;
        return ret;
    }

    static double stod(const std::string& str)
    {
        std::stringstream ss;
        double ret;
        ss << str;
        ss >> ret;
        return ret;
    }

	static std::string get_str_between_two_str(const std::string& s,
										const std::string& start_delim,
										const std::string& stop_delim,
										unsigned& first_delim_pos,
										unsigned& last_delim_pos,
										unsigned& end_pos_of_first_delim)
	{
		first_delim_pos = (unsigned int)s.find(start_delim);

		if (first_delim_pos != std::string::npos)
		{
			end_pos_of_first_delim = first_delim_pos + (unsigned int)start_delim.length();
			if (end_pos_of_first_delim < s.size())
			{
				last_delim_pos = (unsigned int)s.find(stop_delim, end_pos_of_first_delim+1);
				if (last_delim_pos != std::string::npos)
				{
                    if (last_delim_pos > first_delim_pos)
                        return s.substr(first_delim_pos, last_delim_pos - first_delim_pos + 1);
				}
			}
		}
		return "";
	}

	static long long str_to_ll(const std::string& snum)
    {
       long long r = -1;
       try
       {
           r = std::stoll(snum);
       }
       catch (...)
       {
           r = -1;
       }
       return r;
    }

	static bool has_token(const std::string& token, const std::string& line, size_t pos)
	{
		bool r = false;
		if (line.size() >= token.size() + pos)
		{
			std::string s = line.substr(pos, token.size());
			if (s == token)
			{
				r = true;
			}
		}
		return r;
	}

}
}
#endif
