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
	HH			= 50,
	wbaes_512	= 100,
	wbaes_1024	= 200,
	wbaes_2048	= 300,
	wbaes_4096	= 400,
	wbaes_8192	= 500,
	wbaes_16384	= 600,
	wbaes_32768	= 700
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
	// [mode]block;[e]MY_RSAKEY_8100_2023-03-08_11:35:16;[r]MY_RSAKEY_8100_2023-03-08_11:35:16;
	// [mode]recur;[r:]last=10,first=4,rnd=2;[e:]last=10,first=4,rnd=2,new=4;
	keyspec_type ktype 		= keyspec_type::Unknown;

	bool		is_spec		= false;
	uint32_t	first_n 	= 0;
	uint32_t	random_n	= 0;
	uint32_t	last_n		= 0;
	uint32_t	new_n		= 0; // a new ECC private r can by generate then give rg

	std::string	keyname;							// if is_spec == false
	std::vector<std::string> vmaterialized_keyname; // if is_spec == true

    void show()
	{
		if (is_spec)
		{
        	std::cout << "type=" << (long)ktype << ", first_n=" << first_n << ", random_n=" << random_n << ", last_n=" << last_n << std::endl;
			for(size_t i=0;i<vmaterialized_keyname.size();i++)
			{
				std::cout << "      [" << i << "]" << ": " << vmaterialized_keyname[i] << std::endl;
			}
		}
		else
			std::cout << "type=" << (long)ktype << ", keyname=" << keyname << std::endl;
	}
};

struct keyspec_composite
{
	std::vector<keyspec> vkeyspec;
	keyspec_composition_mode mode = keyspec_composition_mode::Recursive;

    void show()
    {
		if (vkeyspec.size() > 1)
		{
			if 		(mode == keyspec_composition_mode::BlockSplit) std::cout << "   mode = block" << std::endl;
			else if (mode == keyspec_composition_mode::Recursive)  std::cout << "   mode = recursive" << std::endl;
		}
        for(size_t i=0;i<vkeyspec.size();i++)
        {
			if (vkeyspec[i].is_spec)
            	std::cout << "   spec [" << i << "]:" ;//<< std::endl;
			else
				std::cout << "   key  [" << i << "]:" ;//<< std::endl;
            vkeyspec[i].show();
        }
    }

	std::string format_key_line(int fmt, bool verbose = false)
	{
        verbose=verbose;
		std::string r;
		if (fmt!=1) return r;

		// TODO...
		// old format, no mixing of recursive keys
		bool 		start_token_done = false;
		std::string start_token;
		keyspec_type start_type;

		for(size_t i=0;i<vkeyspec.size();i++)
        {
			if (vkeyspec[i].is_spec)
            {
				if (vkeyspec[i].vmaterialized_keyname.size() > 0)
				{
					for(size_t j=0;j<vkeyspec[i].vmaterialized_keyname.size();j++)
					{
						if (start_token_done == false)
						{
							if      (vkeyspec[i].ktype == LocalFile) 	start_token = "[l]";
							else if (vkeyspec[i].ktype == WebFile) 		start_token = "[w]";
							else if (vkeyspec[i].ktype == FTPFile) 		start_token = "[f]";
							else if (vkeyspec[i].ktype == VideoFile) 	start_token = "[v]";
							else if (vkeyspec[i].ktype == RSA) 			start_token = "[r]";
							else if (vkeyspec[i].ktype == ECC) 			start_token = "[e]";
							else if (vkeyspec[i].ktype == HH) 			start_token = "[h]";
							else if (vkeyspec[i].ktype == wbaes_512) 	start_token = "[aes512]";
							else if (vkeyspec[i].ktype == wbaes_1024) 	start_token = "[aes1024]";
							else if (vkeyspec[i].ktype == wbaes_2048) 	start_token = "[aes2048]";
							else if (vkeyspec[i].ktype == wbaes_4096) 	start_token = "[aes4096]";
							else if (vkeyspec[i].ktype == wbaes_8192) 	start_token = "[aes8192]";
							else if (vkeyspec[i].ktype == wbaes_16384) 	start_token = "[aes16384]";
							else if (vkeyspec[i].ktype == wbaes_32768) 	start_token = "[aes32768]";
							else
							{
								//...
								continue;
							}

							start_type = vkeyspec[i].ktype;
							start_token_done = true;
							r += start_token;
							r += vkeyspec[i].vmaterialized_keyname[j];
						}
						else if (vkeyspec[i].ktype == start_type)
						{
							r += ";";
							r += vkeyspec[i].vmaterialized_keyname[j];
						}
						else
						{
							// drop...
						}
					}
				}
			}
			else
			{
				if (start_token_done == false)
				{
					if      (vkeyspec[i].ktype == LocalFile) 	start_token = "[l]";
					else if (vkeyspec[i].ktype == WebFile) 		start_token = "[w]";
					else if (vkeyspec[i].ktype == FTPFile) 		start_token = "[f]";
					else if (vkeyspec[i].ktype == VideoFile) 	start_token = "[v]";
					else if (vkeyspec[i].ktype == RSA) 			start_token = "[r]";
					else if (vkeyspec[i].ktype == ECC) 			start_token = "[e]";
					else if (vkeyspec[i].ktype == HH) 			start_token = "[h]";
					else if (vkeyspec[i].ktype == wbaes_512) 	start_token = "[aes512]";
					else if (vkeyspec[i].ktype == wbaes_1024) 	start_token = "[aes1024]";
					else if (vkeyspec[i].ktype == wbaes_2048) 	start_token = "[aes2048]";
					else if (vkeyspec[i].ktype == wbaes_4096) 	start_token = "[aes4096]";
					else if (vkeyspec[i].ktype == wbaes_8192) 	start_token = "[aes8192]";
					else if (vkeyspec[i].ktype == wbaes_16384) 	start_token = "[aes16384]";
					else if (vkeyspec[i].ktype == wbaes_32768) 	start_token = "[aes32768]";
					else
					{
						//...
						continue;
					}
					start_type = vkeyspec[i].ktype;
					start_token_done = true;
					r += start_token;
					r += vkeyspec[i].keyname;
				}
				else if (vkeyspec[i].ktype == start_type)
				{
					r += ";";
					r += vkeyspec[i].keyname;
				}
				else
				{
					// drop...
				}
			}
        }

		return r;
	}
};

class keyspec_parser
{
public:
    keyspec_parser() {}
    ~keyspec_parser() {}

	// Accept global parameters
	// REPEAT all keys generation n times if have [repeat]n
	long repeat = 0;
    std::vector<keyspec_composite> vkeyspec_composite;

	void show()
	{
		std::cout << "--------------------------------------" << std::endl;
		std::cout << "global repeat: "  << repeat << std::endl;
        std::cout << "key lines:     "  << vkeyspec_composite.size() << std::endl;
		std::cout << "--------------------------------------" << std::endl;
        for(size_t i=0;i<vkeyspec_composite.size();i++)
		{
            std::cout << "key line [" << i << "]:" << std::endl;
            vkeyspec_composite[i].show();
		}
		std::cout << "--------------------------------------" << std::endl;
	}

	bool parse_global_param(const std::string& line)
	{
		bool r = false;
		std::vector<std::string> v = split(line, ";");
		for(size_t i=0;i<v.size();i++)
		{
			if (has_token("[repeat]",v[i], 0))
			{
				size_t sz = std::string("[repeat]").size();
				if (v[i].size() > sz)
				{
					std::string s = v[i].substr(sz);
					if (s.size() > 0)
					{
						repeat = (long)strutil::str_to_ll(s);
						if (repeat<0) repeat = 0;
					}
				}
				r = true;
			}
		}
		return r;
	}

    bool parse(cryptodata& data)
    {
        std::vector<std::string> vlines;

        parse_lines(data, vlines);
		for(size_t i=0;i<vlines.size();i++)
		{
			if (parse_global_param(vlines[i]) == true)
			{
			}
			else
			{
				keyspec_composite c = parse_keyspec_composite(vlines[i]);
				if (c.vkeyspec.size() > 0)
					vkeyspec_composite.push_back( c);
			}
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

		keyspec_composition_mode m;
		std::vector<std::string> v = split(line, ";");
		for(size_t i=0;i<v.size();i++)
		{
			if (has_token("[mode]",v[i], 0))
			{
				m = parse_mode(v[i]);
				r.mode = m;
			}
			else if (has_token("[r]",  v[i], 0)) k = parse_key("[r]", 0, keyspec_type::RSA, false, v[i]);
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
			else if (has_token("[aes512]", v[i], 0))  k = parse_key("[aes512]" ,0, keyspec_type::wbaes_512,  false,  v[i]);
			else if (has_token("[aes1024]", v[i], 0)) k = parse_key("[aes1024]",0, keyspec_type::wbaes_1024, false,  v[i]);
			else if (has_token("[aes2048]", v[i], 0)) k = parse_key("[aes2048]",0, keyspec_type::wbaes_2048, false,  v[i]);
			else if (has_token("[aes4096]", v[i], 0)) k = parse_key("[aes4096]",0, keyspec_type::wbaes_4096, false,  v[i]);
			else if (has_token("[aes8192]", v[i], 0)) k = parse_key("[aes8192]",0, keyspec_type::wbaes_8192, false,  v[i]);
			else if (has_token("[aes16384]", v[i], 0)) k = parse_key("[aes16384]",0, keyspec_type::wbaes_16384, false,  v[i]);
			else if (has_token("[aes32768]", v[i], 0)) k = parse_key("[aes32768]",0, keyspec_type::wbaes_32768, false,  v[i]);

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

	keyspec_composition_mode parse_mode(const std::string& keydesc)
	{
		std::string s = keydesc.substr(std::string("[mode]").size());
		if 		(s==std::string("block")) return keyspec_composition_mode::BlockSplit;
		else if (s==std::string("recur")) return keyspec_composition_mode::Recursive;
		else return keyspec_composition_mode::None;
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
						if (eq[1].size()>0)	n = (long)strutil::str_to_ll(eq[1]);
						if (n<0) n = 0;
						r.last_n = n;
					}
					else if (eq[0] == "first")
					{
						if (eq[1].size()>0)	n = (long)strutil::str_to_ll(eq[1]);
						if (n<0) n = 0;
						r.first_n = n;
					}
					else if (eq[0] == "random")
					{
						if (eq[1].size()>0)	n = (long)strutil::str_to_ll(eq[1]);
						if (n<0) n = 0;
						r.random_n = n;
					}
					else if (eq[0] == "new")
					{
						if (eq[1].size()>0)	n = (long)strutil::str_to_ll(eq[1]);
						if (n<0) n = 0;
						r.new_n = n;
					}
				}
			}
		}

		return r;
	}

};


} //namespace
#endif

