#ifndef _INCLUDES_crypto_shuffle
#define _INCLUDES_crypto_shuffle

#include <iostream>
#include "Buffer.hpp"
#include <fstream>
#include <stdio.h>
#include "qa/atomic_bitvector.hpp"

namespace cryptoAL
{

class cryptoshuffle
{
public:
    cryptoshuffle(bool verb = false) {verbose = verb;}
    ~cryptoshuffle() {}

	uint32_t make_uint32(const char* key, uint32_t keypos)
	{
		uint32_t uc[4];
		uint32_t r = 0;

		uc[0]  = (uint32_t)(unsigned char)key[keypos];
		uc[1]  = (uint32_t)(unsigned char)key[keypos+1];
		uc[2]  = (uint32_t)(unsigned char)key[keypos+2];
		uc[3]  = (uint32_t)(unsigned char)key[keypos+3];
		r = 256*256*256*uc[0] + 256*256*uc[1] + 256*uc[2] + uc[3];
		return r;
	}

	uint32_t get_next_free_pos(uint32_t next_pos, atomicbitvector::atomic_bv_t& bitarray)
	{
		uint32_t cnt = 0;
		uint32_t n = (uint32_t)bitarray.size();
		for(size_t i = 0; i< n; i++)
		{
			if (bitarray.test(i) == false)
			{
				if (cnt == next_pos)
				{
					return (uint32_t)i;
				}
				cnt++;
			}
		}

		{
            std::cerr << "ERROR shuffle next_pos " <<  next_pos << std::endl;
            throw "shuffle next_pos";
        }
	}

    virtual bool shuffle(Buffer& buffer, const char* key, uint32_t key_len, uint32_t perc)
    {
		uint32_t remain_len = buffer.size() ;
		uint32_t idx_key = 0;
		uint32_t n;
		uint32_t pos = 0;
		uint32_t next_pos;
		uint32_t next_pos_undone;
		char t;
		uint32_t  cnt = 0;
        bool r = true;

		if (perc > 100) perc = 100;
        uint32_t NPERC = (uint32_t) (buffer.size() * perc / 100.0);

		if (key_len < 16) return r;
		if (buffer.size() < 16) return r;
		if (perc < 1) return r;

		atomicbitvector::atomic_bv_t bitarray(buffer.size());

		while ((remain_len > 1) && (cnt < NPERC))
		{
			while(bitarray.test(pos) == true)
			{
				pos++;
				if (pos >= buffer.size())
				{
					break;
				}
			}
			if (pos >= buffer.size()) break;

			bitarray.set(pos);
			remain_len--;

			n = make_uint32(key, idx_key);
			next_pos = n % remain_len;

			next_pos_undone = get_next_free_pos(next_pos, bitarray);

			if (next_pos_undone >=  buffer.size())
			{
                std::cerr << "ERROR shuffle out of range next_pos_undone: " <<  next_pos_undone << std::endl;
				std::cout << "shuffle key_len " <<  key_len << std::endl;
				std::cout << "shuffle buffer size " <<  buffer.size() << std::endl;
				std::cout << "shuffle swap count " <<  NPERC << std::endl;
                throw "shuffle out of range";
			}

			// swap
			t = buffer.get_at(next_pos_undone);
			buffer.replace_at(next_pos_undone, buffer.get_at(pos));
			buffer.replace_at(pos, t);

			bitarray.set(next_pos_undone);
			remain_len--;

			idx_key += 4;
			if (idx_key > key_len - 4) idx_key=0;

			pos++;
			cnt+=2;
		}

        return r;
    }

    void TEST()
    {
        Buffer b(100);
        std::string s("erfew0-wert9wu098t74etjgto5ituy");
        std::string k("4657456756756757-wert9wu098t74etjgto5ituy");
        b.write(s.data(), (uint32_t)s.size(), 0);
        shuffle(b, k.data(), (uint32_t)k.size(), 100);
        shuffle(b, k.data(), (uint32_t)k.size(), 100);
        for(size_t i = 0; i< s.size(); i++)
		{
			if (s[i] != b.getdata()[i])
			{
                std::cerr << "ERROR shuffle TEST" <<  s << std::endl;
				throw "ERROR shuffle TEST ";
			}
		}
    }


    bool verbose;
};

}
#endif
