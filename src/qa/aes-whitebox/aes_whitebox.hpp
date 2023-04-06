#ifndef _INCLUDES_aes_whitebox_HPP
#define _INCLUDES_aes_whitebox_HPP

#include "../../crypto_const.hpp"
#include "../../random_engine.hpp"
#include "aes_whitebox_base.hpp"
#include "../../c_plus_plus_serializer.h"

namespace WBAES
{

class wbaes512 : public wbaes_base<22, 16>
{
public:
	wbaes512() {}
	~wbaes512() {}
};

class wbaes1024 : public wbaes_base<38, 32>
{
public:
	wbaes1024() {}
	~wbaes1024() {}
};

class wbaes2048 : public wbaes_base<70, 64>
{
public:
	wbaes2048() {}
	~wbaes2048() {}
};

class wbaes4096 : public wbaes_base<134, 128>
{
public:
	wbaes4096() {}
	~wbaes4096() {}
};

class wbaes8192 : public wbaes_base<262, 256>
{
public:
	wbaes8192() {}
	~wbaes8192() {}
};

class wbaes16384 : public wbaes_base<526, 512>
{
public:
	wbaes16384() {}
	~wbaes16384() {}
};

class wbaes32768 : public wbaes_base<1038, 1024>
{
public:
	wbaes32768() {}
	~wbaes32768() {}
};



class wbaes_instance_mgr
{
public:
	~wbaes_instance_mgr()
	{
		if (i512 != nullptr)  {delete i512 ;i512 =nullptr;}
		if (i1024 != nullptr) {delete i1024;i1024=nullptr;}
		if (i2048 != nullptr) {delete i2048;i2048=nullptr;}
		if (i4096 != nullptr) {delete i4096;i4096=nullptr;}
		if (i8192 != nullptr) {delete i8192;i8192=nullptr;}
		if (i16384 != nullptr) {delete i16384;i16384=nullptr;}
		if (i32768 != nullptr) {delete i32768;i32768=nullptr;}
	}

	wbaes_vbase* get_aes()
	{
		if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512) )
		{
			if (i512== nullptr) i512 =  new wbaes512();
			return i512;
		}
		else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024) )
		{
			if (i1024 == nullptr) i1024 = new wbaes1024();
			return i1024;
		}
		else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048) )
		{
			if (i2048 == nullptr) i2048 = new wbaes2048();
			return i2048;
		}
		else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096) )
		{
			if (i4096 == nullptr) i4096 = new wbaes4096();
			return i4096;
		}
		else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192) )
		{
			if (i8192 == nullptr) i8192 = new wbaes8192();
			return i8192;
		}
		else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384) )
		{
			if (i16384 == nullptr) i16384 = new wbaes16384();
			return i16384;
		}
		else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768) )
		{
			if (i32768 == nullptr) i32768 = new wbaes32768();
			return i32768;
		}
		else
		{
			std::cerr << "Name not found " << aes_name << std::endl;
		}
		return nullptr;
	}

	std::string aes_name;
	std::string table_keyname;
	bool table_loaded = false;
	bool table_error = false;

	wbaes512*  i512  = nullptr;
	wbaes1024* i1024 = nullptr;
	wbaes2048* i2048 = nullptr;
	wbaes4096* i4096 = nullptr;
	wbaes8192* i8192 = nullptr;
	wbaes16384* i16384 = nullptr;
	wbaes32768* i32768 = nullptr;

	wbaes_instance_mgr(	const std::string& aesname,
						const std::string& pathtbl,
						const std::string& tablekeyname,
						bool do_loading = true,
						bool verbose = false)
	{
		aes_name = aesname;
		table_keyname = tablekeyname;

		if (do_loading)
			table_loaded = load_tables(pathtbl, verbose);
	}

	bool load_tables(const std::string& pathtbl, [[maybe_unused]]bool verbose = false)
	{
		bool r = true;
		wbaes_vbase* p = get_aes(); // new

		{
			if (cryptoAL::VERBOSE_DEBUG) std::cout << "loading wbaes: " << aes_name  + ", keyname: "  << table_keyname << std::endl;
			{
				std::string filename = pathtbl + aes_name + "_" + table_keyname + "_xor.tbl";

				if (file_util::fileexists(filename)==false)
				{
					std::cerr << "ERROR file not found " << filename << std::endl;
					r = false;
					table_error = true;
					return false;
				}
				if (cryptoAL::VERBOSE_DEBUG) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					if      (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512))  ifd >> bits( ((wbaes512*)p)->Xor);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024)) ifd >> bits( ((wbaes1024*)p)->Xor);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048)) ifd >> bits( ((wbaes2048*)p)->Xor);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096)) ifd >> bits( ((wbaes4096*)p)->Xor);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192)) ifd >> bits( ((wbaes8192*)p)->Xor);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384)) ifd >> bits( ((wbaes16384*)p)->Xor);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768)) ifd >> bits( ((wbaes32768*)p)->Xor);

					ifd.close();

					if (cryptoAL::VERBOSE_DEBUG)
					{
						std::cout << "ok " << filename << std::endl;
						for (int r = 0; r < 2; r++) {
							std::cout << "  {\n";
							for (int n = 0; n < 2; n++) {
							  std::cout << "    {\n";
							  for (int i = 0; i < 2; i++) {
								std::cout << "      { ";
								for (int j = 0; j < 16; j++)
								{
									if      (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512))  std::cout <<  (int)((wbaes512*)p)->Xor[r][n][i][j];
									else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024)) std::cout <<  (int)((wbaes1024*)p)->Xor[r][n][i][j];
									else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048)) std::cout <<  (int)((wbaes2048*)p)->Xor[r][n][i][j];
									else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096)) std::cout <<  (int)((wbaes4096*)p)->Xor[r][n][i][j];
									else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192)) std::cout <<  (int)((wbaes8192*)p)->Xor[r][n][i][j];
									else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384)) std::cout <<  (int)((wbaes16384*)p)->Xor[r][n][i][j];
									else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768)) std::cout <<  (int)((wbaes32768*)p)->Xor[r][n][i][j];
								 }
								std::cout << "},\n";
							  }
							  std::cout <<  "    },\n";
							}
							std::cout <<  "  },\n";
						  }
						 std::cout << "};\n\n";
					 }

				}
				else
				{
					std::cerr << "ERROR reading " << filename << std::endl;
					r = false;
					table_error = true;
					ifd.close();
				}
			}

			if (r)
			{
				std::string filename = pathtbl + aes_name + "_"  + table_keyname + "_tboxesLast.tbl";

				if (file_util::fileexists(filename)==false)
				{
					std::cerr << "ERROR file not found " << filename << std::endl;
					r = false;
					table_error = true;
					return false;
				}
				if (cryptoAL::VERBOSE_DEBUG) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					if      (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512)) ifd >> bits(((wbaes512*)p)->TboxesLast);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024)) ifd >> bits(((wbaes1024*)p)->TboxesLast);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048)) ifd >> bits(((wbaes2048*)p)->TboxesLast);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096)) ifd >> bits(((wbaes4096*)p)->TboxesLast);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192)) ifd >> bits(((wbaes8192*)p)->TboxesLast);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384))ifd >> bits(((wbaes16384*)p)->TboxesLast);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768)) ifd >> bits(((wbaes32768*)p)->TboxesLast);

					ifd.close();
					if (cryptoAL::VERBOSE_DEBUG) std::cout << "ok " << filename << std::endl;
				}
				else
				{
					std::cerr << "ERROR reading " << filename << std::endl;
					r = false;
					table_error = true;
					ifd.close();
				}
			}

			if (r)
			{
				std::string filename = pathtbl + aes_name + "_"  + table_keyname + "_tyboxes.tbl";

				if (file_util::fileexists(filename)==false)
				{
					std::cerr << "ERROR file not found " << filename << std::endl;
					r = false;
					table_error = true;
					return false;
				}
				if (cryptoAL::VERBOSE_DEBUG) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					if      (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512))  ifd >> bits(((wbaes512*)p)->Tyboxes);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024)) ifd >> bits(((wbaes1024*)p)->Tyboxes);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048)) ifd >> bits(((wbaes2048*)p)->Tyboxes);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096)) ifd >> bits(((wbaes4096*)p)->Tyboxes);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192)) ifd >> bits(((wbaes8192*)p)->Tyboxes);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384)) ifd >> bits(((wbaes16384*)p)->Tyboxes);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768)) ifd >> bits(((wbaes32768*)p)->Tyboxes);

					ifd.close();
					if (cryptoAL::VERBOSE_DEBUG) std::cout << "ok " << filename << std::endl;
				}
				else
				{
					std::cerr << "ERROR reading " << filename << std::endl;
					r = false;
					table_error = true;
					ifd.close();
				}
			}

			if (r)
			{
				std::string filename = pathtbl + aes_name + "_"  + table_keyname + "_mbl.tbl";

				if (file_util::fileexists(filename)==false)
				{
					std::cerr << "ERROR file not found " << filename << std::endl;
					r = false;
					table_error = true;
					return false;
				}
				if (cryptoAL::VERBOSE_DEBUG) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					if      (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512))  ifd >> bits(((wbaes512*)p)->MBL);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024)) ifd >> bits(((wbaes1024*)p)->MBL);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048)) ifd >> bits(((wbaes2048*)p)->MBL);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096)) ifd >> bits(((wbaes4096*)p)->MBL);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192))  ifd >> bits(((wbaes8192*)p)->MBL);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384)) ifd >> bits(((wbaes16384*)p)->MBL);
					else if (aes_name == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768)) ifd >> bits(((wbaes32768*)p)->MBL);

					ifd.close();
					if (cryptoAL::VERBOSE_DEBUG) std::cout << "ok " << filename << std::endl;
				}
				else
				{
					std::cerr << "ERROR reading " << filename << std::endl;
					r = false;
					table_error = true;
					ifd.close();
				}
			}
		}
		return r;
	}
};

struct wbaes_file
{
	wbaes_file()  	{};
	~wbaes_file()	{};

	wbaes_file(const std::string& iaes_type, const std::string& ikeyname, const std::string& ifolder)
		: aes_type(iaes_type), keyname(ikeyname), folder(ifolder)
    {
    }

	std::string key() {return folder + "_" + aes_type + "_" + keyname;}
	std::string aes_type;
	std::string keyname;
	std::string folder;
};

// TODO maintain a limit number in memory - otherwise may exhaust memory...
// We may want to use near "maximum" memory for whitebox to prevent transfer of memory to web
// AES 32k == 64MB
// void* malloc (size_t size); //No-throw guarantee: this function never throws exceptions.
// If the function failed to allocate the requested block of memory, a null pointer is returned
// void free (void* ptr); //If ptr is a null pointer, the function does nothing.
class wbaes_pool
{
	const size_t WBAES_LIM = 10;

public:
	std::map<std::string, wbaes_instance_mgr*> map_wbaes_instance;

	wbaes_pool() {}
	~wbaes_pool()
	{
		for(auto& [akey, amgr] : map_wbaes_instance)
		{
            wbaes_instance_mgr* pmgr = map_wbaes_instance[akey];
			if (pmgr!=nullptr)
			{
				delete pmgr;
				pmgr = nullptr;
				map_wbaes_instance[akey] = nullptr;
			}
		}
	}

	void remove_one_except(const std::string& key)
	{
		for(auto& [k, d] : map_wbaes_instance)
		{
			if (k != key)
			{
				wbaes_instance_mgr* pmgr = map_wbaes_instance[k];
				if (pmgr != nullptr)
				{
					delete pmgr;
					pmgr = nullptr;
					map_wbaes_instance[k] = nullptr;
				}
				map_wbaes_instance.erase(k);
				break;
			}
		}
	}

	wbaes_vbase* get_aes_instance(const std::string& iaes_type, const std::string& ikeyname, const std::string& ifolder, bool verbose=false)
	{
		wbaes_vbase* r = nullptr;
		wbaes_file fkey(iaes_type, ikeyname, ifolder);
		std::string key = fkey.key();

		if (map_wbaes_instance.find(key) != map_wbaes_instance.end() )
		{
			wbaes_instance_mgr* ptr_aes_instance_mgr = map_wbaes_instance[key];
			if (ptr_aes_instance_mgr != nullptr)
			{
				r = ptr_aes_instance_mgr->get_aes();
			}
			else
			{
				// ?
				std::cerr << "ERROR aes files not in memory " << key << std::endl;
			}
		}
		else
		{
			// TODO catch the std::bad_alloc
			wbaes_instance_mgr* ptr_aes_instance_mgr = new wbaes_instance_mgr(iaes_type, ifolder, ikeyname, true, verbose);
			if (ptr_aes_instance_mgr->table_error == true)
			{
				std::cerr << "ERROR reading aes files " << key << std::endl;
				delete ptr_aes_instance_mgr;
			}
			else if (ptr_aes_instance_mgr->table_loaded == false)
			{
				std::cerr << "ERROR loading aes files " << key << std::endl;
				delete ptr_aes_instance_mgr;
			}
			else
			{
				if (map_wbaes_instance.size() >= WBAES_LIM)
				{
					remove_one_except(key);
				}

				map_wbaes_instance[key] = ptr_aes_instance_mgr;
				r = ptr_aes_instance_mgr->get_aes();
			}
		}
		return r;
	}

};

[[maybe_unused]] static bool validate_wbaes_key(WBAES::wbaes_vbase* paes, bool verbose=true)
{
	if (paes==nullptr) return false;
	bool r = true;
	int N = 2 * paes->key_length(); // 2x test

	std::string splain 		= cryptoAL::random::generate_base16_random_string(2*N); // 2 * for base16
	std::string splaincopy 	= splain;
	size_t plainLen = splain.size();

	std::vector<uint8_t> eout(plainLen, 0);
	std::vector<uint8_t> dout(plainLen, 0);

	//NO KEY!!!!!!!!!!!!!!!!!! but BIG *.tbl
	const unsigned char iv[16] = {0x60, 0x61, 0x82, 0x93, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

	// aes
	const size_t MAX_DISPLAY = 64;
	if (verbose) std::cout << "WBAES test message   : ";
	for(size_t i=0;i<std::min(MAX_DISPLAY, plainLen);i++) std::cout << (int)splain[i];
	if (verbose) std::cout << "..." <<std::endl;

	paes->aes_whitebox_encrypt_cfb(iv, (uint8_t*)splaincopy.data(), plainLen, eout.data());
	if (verbose) std::cout << "WBAES encrypt message: ";
	for(size_t i=0;i<std::min(MAX_DISPLAY, plainLen);i++) std::cout << (int)eout[i];
	if (verbose) std::cout << "..." <<std::endl;

	paes->aes_whitebox_decrypt_cfb(iv, eout.data(), plainLen, dout.data());
	if (verbose) std::cout << "WBAES decrypt message: ";
	for(size_t i=0;i<std::min(MAX_DISPLAY, plainLen);i++) std::cout << (int)dout[i];
	if (verbose) std::cout << "..." << std::endl;

	for(size_t i=0;i<plainLen;i++)
	{
		if (dout[i] != splain[i])
		{
			std::cerr << "Error with WBAES "<< i <<std::endl;
			std::cerr << (int)dout[i]<<std::endl;
			std::cerr << (int)splain[i]<<std::endl;
			r = false;
			break;
		}
	}
	if (r)
	{
		if (verbose)
			std::cout << "WBAES key OK"<<std::endl;
	}
	return r;
}


}  // namespace

#endif
