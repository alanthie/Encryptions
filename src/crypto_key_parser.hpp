#ifndef CRYPTO_KEYPARSER_H_INCLUDED
#define CRYPTO_KEYPARSER_H_INCLUDED

#include "crypto_const.hpp"
#include <iostream>
#include "crypto_strutil.hpp"
#include "data.hpp"

namespace cryptoAL
{

enum keyspec_type
{
	Unknown		= 0,
	LocalFile	= 10,
	WebFile		= 20,
	FTPFile		= 22,
	VideoFile	= 24,
	RSA			= 30,
	ECC			= 40,
	HH			= 50
};

enum keyspec_composition_mode
{
	None		= 0,
	Recursive	= 1,
	BlockSplit	= 2
};

struct keyspec
{
	// [e]MY_RSAKEY_8100_2023-03-08_11:35:16
	// [e]MY_RSAKEY_8100_2023-03-08_11:35:16;[r]MY_RSAKEY_8100_2023-03-08_11:35:16;
	// [r:]last=10,first=4,rnd=2;[h:]last=10,first=4,rnd=2;
	keyspec_type ktype 		= keyspec_type::Unknown;
	bool		is_spec		= false;
	uint32_t	first_n 	= 0;
	uint32_t	random_n	= 0;
	uint32_t	last_n		= 0;
	std::string	keyname;

    void show()
	{
        std::cout << "key type " << (long)ktype << " is_spec " << is_spec << " keyname " << keyname << " first_n " << first_n << " random_n " << random_n << " last_n " << last_n << std::endl;
	}
};

struct keyspec_composite
{
	std::vector<keyspec> vkeyspec;
	keyspec_composition_mode mode = keyspec_composition_mode::None;

    void show()
    {
        //std::cout << "vkeyspec size " << vkeyspec.size() << std::endl;
        for(size_t i=0;i<vkeyspec.size();i++)
        {
            std::cout << "vkeyspec [" << i << "]" ;//<< std::endl;
            vkeyspec[i].show();
        }
    }
};

class keyspec_parser
{
public:
    keyspec_parser() {}
    ~keyspec_parser() {}

    std::vector<keyspec_composite> vkeyspec_composite;

	void show()
	{
        std::cout << "vkeyspec_composite size "  << vkeyspec_composite.size() << std::endl;
        for(size_t i=0;i<vkeyspec_composite.size();i++)
		{
            std::cout << "vkeyspec_composite [" << i << "]" << std::endl;
            vkeyspec_composite[i].show();
		}
	}

	// [e]MY_RSAKEY_8100_2023-03-08_11:35:16
	// [e]MY_RSAKEY_8100_2023-03-08_11:35:16;[r]MY_RSAKEY_8100_2023-03-08_11:35:16;
	// [r:]last=10,first=4,random=2;[h:]last=10,first=4,random=2;
    bool parse(cryptodata& data)
    {
        std::vector<std::string> vlines;

        parse_lines(data, vlines);
		for(size_t i=0;i<vlines.size();i++)
		{
			keyspec_composite c = parse_keyspec_composite(vlines[i]);
			if (c.vkeyspec.size() > 0)
                vkeyspec_composite.push_back( c);
		}
		return true;
    }

	void parse_lines(cryptodata& urls_data, std::vector<std::string>& vlines)
    {
	    char c;

        char url[URL_MAX_SIZE] = { 0 };
        int pos = -1;
        uint32_t idx=0;

        vlines.clear();

		for(size_t i=0;i<urls_data.buffer.size();i++)
		{
			c = urls_data.buffer.getdata()[i];
			pos++;

			if ((c == '\n') || (i==urls_data.buffer.size()-1))
			{
				if (i==urls_data.buffer.size()-1)
				{
					if ((c!=0) && (c!='\r') && (c!='\n'))
					{
						url[idx] = c;
						idx++;
					}
				}

				uint32_t len = idx;

				if ( ((len >= URL_MIN_SIZE) && (len <= URL_MAX_SIZE)) && (url[0]!=';') )
				{
					std::string su(url);
					su = strutil::trim_copy(su);
					vlines.push_back(su);
				}
				else
				{
					// skip!
				}

				for(uint32_t ii=0;ii<URL_MAX_SIZE;ii++) url[ii] = 0;
				pos = -1;
				idx = 0;
			}
			else
			{
				if ((c!=0) && (c!='\r') && (c!='\n'))
				{
					if (idx < URL_MAX_SIZE)
					{
						url[idx] = c;
						idx++;
					}
				}
			}
		}
    }

	keyspec_composite parse_keyspec_composite(const std::string& line)
	{
		keyspec_composite r;
		keyspec k;

		std::vector<std::string> v = split(line, ";");
		for(size_t i=0;i<v.size();i++)
		{
			if 		(has_token("[r]",  v[i], 0)) k = parse_key("[r]", 0, keyspec_type::RSA, false, v[i]);
			else if (has_token("[r:]", v[i], 0)) k = parse_key("[r:]",0, keyspec_type::RSA, true,  v[i]);
			else if (has_token("[e]",  v[i], 0)) k = parse_key("[e]", 0, keyspec_type::ECC, false, v[i]);
			else if (has_token("[e:]", v[i], 0)) k = parse_key("[e:]",0, keyspec_type::ECC, true,  v[i]);
			else if (has_token("[h]",  v[i], 0)) k = parse_key("[h]", 0, keyspec_type::HH, false, v[i]);
			else if (has_token("[h:]", v[i], 0)) k = parse_key("[h:]",0, keyspec_type::HH, true,  v[i]);
			else if (has_token("[l]",  v[i], 0)) k = parse_key("[l]", 0, keyspec_type::LocalFile, false, v[i]);
			else if (has_token("[l:]", v[i], 0)) k = parse_key("[l:]",0, keyspec_type::LocalFile, true,  v[i]);
			else if (has_token("[w]",  v[i], 0)) k = parse_key("[w]", 0, keyspec_type::WebFile, false, v[i]);
			else if (has_token("[w:]", v[i], 0)) k = parse_key("[w:]",0, keyspec_type::WebFile, true,  v[i]);
			else if (has_token("[v]",  v[i], 0)) k = parse_key("[v]", 0, keyspec_type::VideoFile, false, v[i]);
			else if (has_token("[v:]", v[i], 0)) k = parse_key("[v:]",0, keyspec_type::VideoFile, true,  v[i]);
			else if (has_token("[f]",  v[i], 0)) k = parse_key("[f]", 0, keyspec_type::FTPFile, false, v[i]);
			else if (has_token("[f:]", v[i], 0)) k = parse_key("[f:]",0, keyspec_type::FTPFile, true,  v[i]);

			if (k.ktype != keyspec_type::Unknown)
			{
				r.vkeyspec.push_back(k);
			}
		}
		return r;
	}

	bool has_token(const std::string& token, const std::string& line, size_t pos)
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

	keyspec parse_key(const std::string& token, size_t pos, keyspec_type t, bool is_spec, const std::string& keydesc)
	{
		keyspec r;

		r.ktype 	= t;
		r.is_spec 	= is_spec;

		if (is_spec == false)
		{
			r.keyname = keydesc.substr(token.size() + pos);
		}
		else
		{
			std::string s = keydesc.substr(token.size() + pos);

			std::vector<std::string> v = split(s, ",");
			for(size_t i=0;i<v.size();i++)
			{
				long n = 0;
				std::vector<std::string> eq = split(v[i], "=");

				if (eq.size() >= 2)
				{
					if (eq[0] == "last")
					{
						if (eq[1].size()>0)
							n = strutil::stol(eq[1]);
						if (n<0) n = 0;
						r.last_n = n;
					}
					else if (eq[0] == "first")
					{
						if (eq[1].size()>0)
							n = strutil::stol(eq[1]);
						if (n<0) n = 0;
						r.first_n = n;
					}
					else if (eq[0] == "random")
					{
						if (eq[1].size()>0)
							n = strutil::stol(eq[1]);
						if (n<0) n = 0;
						r.random_n = n;
					}
				}
			}
		}

		return r;
	}

};


} //namespace
#endif

