#ifndef FILE_UTIL_H_INCLUDED
#define FILE_UTIL_H_INCLUDED

#include "crypto_const.hpp"
#include "data.hpp"
#include "SHA256.h"
#include "common/includes.h" // makehex
#include <filesystem>

namespace file_util
{
    [[maybe_unused]] static  bool fileexists(const std::filesystem::path& p, std::filesystem::file_status s = std::filesystem::file_status{})
	{
		if(std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists(p))
			return true;
		else
			return false;
	}

	[[maybe_unused]] static std::string get_current_dir()
	{
		return std::filesystem::current_path();
	}

	[[maybe_unused]] static int32_t filesize(std::string filename)
	{
		int32_t sz = -1;
		std::ifstream ifd(filename.data(), std::ios::binary | std::ios::ate);
		if (ifd)
		{
			sz = (int32_t)ifd.tellg();
		}
		ifd.close();
		return sz;
	}

	[[maybe_unused]] static bool is_file_same(std::string filename1, std::string filename2)
	{
		cryptoAL::cryptodata data1;
		cryptoAL::cryptodata data2;

		if(data1.read_from_file(filename1)==false)
			return false;

		if(data2.read_from_file(filename2)==false)
			return false;

		if(data1.buffer.size() != data2.buffer.size() )
			return false;

		for(size_t i=0;i< data1.buffer.size() ; i++)
		{
			if ( data1.buffer.getdata()[i] != data2.buffer.getdata()[i])
				return false;
		}
		return true;
	}

	[[maybe_unused]] static std::string file_checksum(std::string filename)
	{
		std::string s = "";
		cryptoAL::cryptodata temp;
		bool r = temp.read_from_file(filename);
		if (r==true)
		{
			SHA256 sha;
			sha.update(reinterpret_cast<const uint8_t*> (temp.buffer.getdata()), temp.buffer.size() );
			uint8_t* digest = sha.digest();
			s = SHA256::toString(digest);
			delete[] digest;
		}
		else
		{
			std::cerr << "ERROR reading " << filename << ", code: " << r << std::endl;
		}
		return s;
	}

	[[maybe_unused]] static std::string HEX(std::string sfile, long long pos, long long keysize)
	{
		bool r = true;
		if (file_util::fileexists(sfile) == false)
		{
			 std::cerr <<  "ERROR File not found - check the file path " << sfile<< std::endl;
			 return "";
		}
		if (pos < 0)
		{
			 std::cerr <<  "WARNING position less than 0 - reset to 0 " << std::endl;
			 pos = 0;
		}
		if (keysize < 1)
		{
			 std::cerr <<  "WARNING keysize less than one - reset to 1 " << std::endl;
			 keysize = 1;
		}

		cryptoAL::cryptodata d;
		r = d.read_from_file(sfile);
		if (r == false)
		{
			 std::cerr <<  "ERROR Unable to read file " + sfile<< std::endl;
			 return "";
		}

		long long len = (long long)d.buffer.size();
		if (pos + keysize >= len)
		{
			std::cerr << "ERROR key pos+len bigger then file size: " << len << std::endl;
			return "";
		}

		cryptoAL::Buffer b;
		b.increase_size((uint32_t)keysize);
		b.write(&d.buffer.getdata()[pos], (uint32_t)keysize, 0);

		std::string hex;
		char c;
		for(long long i=0;i<keysize;i++)
		{
			c = b.getdata()[i];
			hex += makehex((char)c, 2);
		}

		return hex;
	}

	[[maybe_unused]] static void show_summary(const char* buffer, uint32_t buf_len)
	{
		for( uint32_t j = 0; j< buf_len; j++)
		{
			if (j<16) std::cout << (int)(unsigned char)buffer[j] << " ";
			else if (j==16) {std::cout << " ... [" << buf_len << "] ... ";}
			else if (j>buf_len-16) std::cout << (int)(unsigned char)buffer[j] << " ";
		}
		std::cout <<  std::endl;
	}

	[[maybe_unused]] static std::string get_summary_hex(const char* buffer, uint32_t buf_len)
	{
		std::string s;
		for( uint32_t j = 0; j< buf_len; j++)
		{
			if (j<16) {s+= makehex((char)buffer[j], 2); s+= " ";}
			else if (j==16) {s+= " ... ["; s+= std::to_string(buf_len); s+= "] ... ";}
			else if (j>buf_len-16) { s+=  makehex((char)buffer[j], 2); s+=" ";}
		}
		return s;
	}
}
#endif
