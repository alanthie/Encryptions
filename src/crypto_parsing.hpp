#ifndef _INCLUDES_crypto_parsing
#define _INCLUDES_crypto_parsing

#include "crypto_const.hpp"
#include <filesystem>
#include <curl/curl.h>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>
#include "data.hpp"

namespace cryptoAL
{
    static std::string get_current_time_and_date_short()
    {
       auto now = std::chrono::system_clock::now();
       auto in_time_t = std::chrono::system_clock::to_time_t(now);

       std::stringstream ss;
       ss << std::put_time(std::localtime(&in_time_t), "%Y%m%d%H%M%S");
       //std::cout << "get_current_time_and_date: " << ss.str()  << std::endl;
       return ss.str();
    }
    static std::string get_current_time_and_date()
    {
       auto now = std::chrono::system_clock::now();
       auto in_time_t = std::chrono::system_clock::to_time_t(now);

       std::stringstream ss;
       ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d_%X");
       //std::cout << "get_current_time_and_date: " << ss.str()  << std::endl;
       return ss.str();
    }

    static std::string get_current_date()
    {
       auto now = std::chrono::system_clock::now();
       auto in_time_t = std::chrono::system_clock::to_time_t(now);

       std::stringstream ss;
       ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d");
       return ss.str();
    }

    static int find_string(std::string url, char delim, std::string vlist, [[maybe_unused]] bool verbose = false)
    {
       size_t pos_start = 0;
       size_t pos_end = 0;
       std::string  token;
       int cnt = 0;

       if (VERBOSE_DEBUG)
           std::cout << "searching for match of "<< url << " in list " << vlist << std::endl;

       for(size_t i=0;i<vlist.size();i++)
       {
           if (vlist[i]!=delim) pos_end++;
           else
           {
               token = vlist.substr(pos_start, pos_end-pos_start);
               if (VERBOSE_DEBUG)
                   std::cout << "token "<< token << std::endl;
               if (url.find(token, 0) != std::string::npos)
               {
                   return cnt;
               }
               pos_start = pos_end+1;
               cnt++;
           }
       }
       return -1;
    }

    static std::string get_string_by_index(std::string vlist, char delim, int idx, [[maybe_unused]] bool verbose = false)
    {
       size_t pos_start = 0;
       size_t pos_end = 0;
       std::string token;
       int cnt = 0;

       for(size_t i=0;i<vlist.size();i++)
       {
           if (vlist[i]!=delim) pos_end++;
           else
           {
               token = vlist.substr(pos_start, pos_end-pos_start);
               if (VERBOSE_DEBUG)
                   std::cout << "token "<< token << std::endl;
               if (idx == cnt)
                   return token;

               pos_start = pos_end+1;
               i = pos_start;
               cnt++;
           }
       }
       return "";
    }

    static std::vector<std::string> split(std::string s, std::string delimiter)
    {
       std::vector<std::string> res;
       if (s.size() == 0) return res;

       try
       {
           size_t pos_start = 0;
           size_t pos_end;
           size_t delim_len = delimiter.length();
           std::string token;

           while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos)
           {
               token = s.substr (pos_start, pos_end - pos_start);
               pos_start = pos_end + delim_len;
               res.push_back (token);

               if (pos_start >= s.size()) break;
           }
           if (pos_start < s.size())
               res.push_back (s.substr (pos_start));
       }
       catch(...)
       {
           std::cerr << "ERROR in split" << std::endl;
       }
       return res;
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

    static std::string get_block(std::string s, std::string start, std::string last)
    {
       size_t pos_start = 0;
       size_t pos_end;
       if ((pos_start = s.find(start, 0)) != std::string::npos)
       {
           if ((pos_end = s.find(last, pos_start)) != std::string::npos)
           {
               if (pos_end  > (pos_start + start.size())  )
                   return s.substr(pos_start+start.size(), pos_end - (pos_start+start.size()) );
           }
       }
       return "";
    }

    static std::string remove_hex_delim(const std::string& s)
    {
        std::string r ;
        long long n = s.size();
        for(long long i=0;i<n;i++)
        {
            if ( (s[i]!=' ') && (s[i]!=':') && (s[i]!='\n') && (s[i]!='\r') )
                r+=s[i];
        }
        return r;
    }

    static std::string remove_hex2_delim(const std::string& s)
    {
        std::string r ;
        long long n = s.size();
        for(long long i=0;i<n;i++)
        {
            if ( (s[i]!=' ') && (s[i]!=':') && (s[i]!='\n') && (s[i]!='\r') && (s[i]!='\"') && (s[i]!='}') )
                r+=s[i];
        }

        if (r.size() >= 2)
        {
            if ((r[0]=='0') && (r[1]=='x'))
            {
                r = r.substr(2);
            }
        }
        return r;
    }

    static std::string remove_delim(const std::string& s, char delim)
    {
        std::string r ;
        long long n = s.size();
        for(long long i=0;i<n;i++)
        {
            if (s[i]!=delim)
                r+=s[i];
        }
        return r;
    }

    //namespace fs = std::filesystem;
    static bool fileexists2(const std::filesystem::path& p, std::filesystem::file_status s = std::filesystem::file_status{})
    {
        if(std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists(p))
            return true;
        else
            return false;
    }

    static std::string get_block_infile(std::string FILE, std::string start, std::string last)
    {
        if (fileexists2(FILE))
        {
            cryptodata d;
            bool b = d.read_from_file(FILE);
            if (b)
            {
                std::string s(d.buffer.getdata());
                size_t pos_start = 0;
                size_t pos_end;
                if ((pos_start = s.find(start, 0)) != std::string::npos)
                {
                    //std::cerr << "start: " << pos_start << std::endl;
                    if ((pos_end = s.find(last, pos_start)) != std::string::npos)
                    {
                        //std::cerr << "end: " << pos_start << std::endl;
                        if (pos_end  > (pos_start + start.size())  )
                            return s.substr(pos_start+start.size(), pos_end - (pos_start+start.size()) );
                        else
                            std::cerr << "end overflow: " <<  last << std::endl;

                    }
                    else
                        std::cerr << "start failed: " << start << std::endl;
                }
                else
                        std::cerr << "end failed: " << last << std::endl;
            }
            else
            {
                std::cerr << "ERROR reading file: " << FILE << std::endl;
            }
        }
        else
        {
            std::cerr << "ERROR no file: " << FILE << std::endl;
        }

        std::cerr << "get_block_infile failed" << std::endl;
       return "";
    }


}
#endif

