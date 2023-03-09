#ifndef _INCLUDES_crypto_parsing
#define _INCLUDES_crypto_parsing

#include <filesystem>
#include <curl/curl.h>
#include "encrypt.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>
#include "base_const.hpp"
#include "crypto_file.hpp"

namespace cryptoAL
{
std::string get_current_time_and_date()
{
   auto now = std::chrono::system_clock::now();
   auto in_time_t = std::chrono::system_clock::to_time_t(now);

   std::stringstream ss;
   ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d_%X");
   return ss.str();
}

std::string get_current_date()
{
   auto now = std::chrono::system_clock::now();
   auto in_time_t = std::chrono::system_clock::to_time_t(now);

   std::stringstream ss;
   ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d");
   return ss.str();
}

int find_string(std::string url, char delim, std::string vlist, bool verbose = false)
{
   size_t pos_start = 0;
   size_t pos_end = 0;
   std::string  token;
   int cnt = 0;

   if (verbose)
       std::cout << "searching for match of "<< url << " in list " << vlist << std::endl;

   for(size_t i=0;i<vlist.size();i++)
   {
       if (vlist[i]!=delim) pos_end++;
       else
       {
           token = vlist.substr(pos_start, pos_end-pos_start);
           if (verbose)
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

std::string get_string_by_index(std::string vlist, char delim, int idx, bool verbose = false)
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
           if (verbose)
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

std::vector<std::string> split(std::string s, std::string delimiter)
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

long long str_to_ll(const std::string& snum)
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

std::string get_block(std::string s, std::string start, std::string last)
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

std::string remove_hex_delim(std::string s)
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


std::string get_block_infile(std::string FILE, std::string start, std::string last)
{
	//if (fileexists(FILE))
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
			   if ((pos_end = s.find(last, pos_start)) != std::string::npos)
			   {
				   if (pos_end  > (pos_start + start.size())  )
					   return s.substr(pos_start+start.size(), pos_end - (pos_start+start.size()) );
			   }
			}
		}
   }
//   else
//   	std::cerr << "no file: " << FILE << std::endl;

   return "";
}

//std::string remove_hex_delim(std::string s)
//{
//   std::string r ;
//   long long n = s.size();
//   for(long long i=0;i<n;i++)
//   {
//       if ( (s[i]!=' ') && (s[i]!=':') && (s[i]!='\n') && (s[i]!='\r') )
//           r+=s[i];
//   }
//   return r;
//}

}
#endif
