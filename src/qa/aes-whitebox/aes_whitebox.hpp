#ifndef _INCLUDES_aes_whitebox_HPP
#define _INCLUDES_aes_whitebox_HPP

#include "../../base_const.hpp"

#ifdef _WIN32
#else
#ifdef HAS_WHITEBOX_AES_FEATURE
#include "aes_whitebox.h"
//-lntl -lpthread -lgmp
//#include "aes_whitebox_tables.cc"
#include <NTL/mat_GF2.h>
#include "aes_private.h"
#include <iostream>
#include "../../c_plus_plus_serializer.h"

namespace WBAES
{

class wbaes512
{
public:
	int Nk = 16;
	int Nr = 22;
	std::array< std::array< std::array< std::array<uint8_t, 16>, 16>, 96>, 21> Xor;
	std::array< std::array< std::array< uint32_t, 256>, 16>, 21> Tyboxes;
	std::array< std::array< uint8_t,  256>, 16> TboxesLast;
	std::array< std::array< std::array< uint32_t, 256>, 16>, 21> MBL;

	void ShiftRows(uint8_t state[16])
	{
	  constexpr int shifts[16] = {
		 0,  5, 10, 15,
		 4,  9, 14,  3,
		 8, 13,  2,  7,
		12,  1,  6, 11,
	  };

	  const uint8_t in[16] = {
		state[ 0], state[ 1], state[ 2], state[ 3],
		state[ 4], state[ 5], state[ 6], state[ 7],
		state[ 8], state[ 9], state[10], state[11],
		state[12], state[13], state[14], state[15],
	  };

	  for (int i = 0; i < 16; i++)
		state[i] = in[shifts[i]];
	}

	void Cipher(uint8_t in[16]) {
	  // Perform the necessary number of rounds. The round key is added first.
	  // The last round does not perform the MixColumns step.

	  std::cout << "Cipher Nr: " << Nr << std::endl;
	  for (int r = 0; r < Nr-1; r++) {
		ShiftRows(in);

		// Using T-boxes + Ty(i) Tables (single step):
		for (int j = 0; j < 4; ++j) {
		  uint8_t n0, n1, n2, n3;
		  uint32_t aa, bb, cc, dd;

		  aa = Tyboxes[r][j*4 + 0][in[j*4 + 0]],
		  bb = Tyboxes[r][j*4 + 1][in[j*4 + 1]],
		  cc = Tyboxes[r][j*4 + 2][in[j*4 + 2]],
		  dd = Tyboxes[r][j*4 + 3][in[j*4 + 3]];

		  n0 = Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
		  n1 = Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
		  n2 = Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
		  n3 = Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
		  in[j*4 + 0] = (Xor[r][j*24 + 4][n0][n1] << 4) | Xor[r][j*24 + 5][n2][n3];

		  n0 = Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
		  n1 = Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
		  n2 = Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
		  n3 = Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
		  in[j*4 + 1] = (Xor[r][j*24 + 10][n0][n1] << 4) | Xor[r][j*24 + 11][n2][n3];

		  n0 = Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
		  n1 = Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
		  n2 = Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
		  n3 = Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
		  in[j*4 + 2] = (Xor[r][j*24 + 16][n0][n1] << 4) | Xor[r][j*24 + 17][n2][n3];

		  n0 = Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
		  n1 = Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
		  n2 = Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
		  n3 = Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
		  in[j*4 + 3] = (Xor[r][j*24 + 22][n0][n1] << 4) | Xor[r][j*24 + 23][n2][n3];

		  aa = MBL[r][j*4 + 0][in[j*4 + 0]];
		  bb = MBL[r][j*4 + 1][in[j*4 + 1]];
		  cc = MBL[r][j*4 + 2][in[j*4 + 2]];
		  dd = MBL[r][j*4 + 3][in[j*4 + 3]];

		  n0 = Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
		  n1 = Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
		  n2 = Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
		  n3 = Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
		  in[j*4 + 0] = (Xor[r][j*24 + 4][n0][n1] << 4) | Xor[r][j*24 + 5][n2][n3];

		  n0 = Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
		  n1 = Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
		  n2 = Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
		  n3 = Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
		  in[j*4 + 1] = (Xor[r][j*24 + 10][n0][n1] << 4) | Xor[r][j*24 + 11][n2][n3];

		  n0 = Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
		  n1 = Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
		  n2 = Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
		  n3 = Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
		  in[j*4 + 2] = (Xor[r][j*24 + 16][n0][n1] << 4) | Xor[r][j*24 + 17][n2][n3];

		  n0 = Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
		  n1 = Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
		  n2 = Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
		  n3 = Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
		  in[j*4 + 3] = (Xor[r][j*24 + 22][n0][n1] << 4) | Xor[r][j*24 + 23][n2][n3];
		}
	  }

	  ShiftRows(in);

	  // Using T-boxes:
	  for (int i = 0; i < 16; i++)
		in[i] = TboxesLast[i][in[i]];
	}


	void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m, size_t len, uint8_t* c)
	 {
	  uint8_t cfb_blk[16];

	  for (int i = 0; i < 16; i++)
		cfb_blk[i] = iv[i];

	  for (size_t i = 0; i < len; i++)
	  {
		if ((i & 0xf) == 0)
		  Cipher(cfb_blk);
		cfb_blk[i & 0xf] ^= m[i];
		c[i] = cfb_blk[i & 0xf];
	  }
	}

	void aes_whitebox_decrypt_cfb(const uint8_t iv[16], const uint8_t* c, size_t len, uint8_t* m)
	{
	  uint8_t cfb_blk[16];

	  for (int i = 0; i < 16; i++)
		cfb_blk[i] = iv[i];

	  for (size_t i = 0; i < len; i++) {
		if ((i & 0xf) == 0)
		  Cipher(cfb_blk);
		m[i] = cfb_blk[i & 0xf] ^ c[i];
		cfb_blk[i & 0xf] = c[i];
	  }
	}

	void aes_whitebox_encrypt_ofb(const uint8_t iv[16], const uint8_t* m,
		size_t len, uint8_t* c) {
	  uint8_t cfb_blk[16];

	  for (int i = 0; i < 16; i++)
		cfb_blk[i] = iv[i];

	  for (size_t i = 0; i < len; i++) {
		if ((i & 0xf) == 0)
		  Cipher(cfb_blk);
		c[i] = m[i] ^ cfb_blk[i & 0xf];
	  }
	}

	void aes_whitebox_decrypt_ofb(const uint8_t iv[16], const uint8_t* c,
		size_t len, uint8_t* m) {
	  aes_whitebox_encrypt_ofb(iv, c, len, m);
	}

	void aes_whitebox_encrypt_ctr(const uint8_t nonce[16], const uint8_t* m,
		size_t len, uint8_t* c) {
	  uint8_t counter[16], buf[16];

	  for (int i = 0; i < 16; i++)
		counter[i] = nonce[i];

	  for (size_t i = 0; i < len; i++) {
		if ((i & 0xf) == 0) {
		  for (int j = 0; j < 16; j++)
			buf[j] = counter[j];
		  Cipher(buf);
		  for (int j = 15; j >= 0; j--) {
			counter[j]++;
			if (counter[j])
			  break;
		  }
		}
		c[i] = m[i] ^ buf[i & 0xf];
	  }
	}

	void aes_whitebox_decrypt_ctr(const uint8_t nonce[16], const uint8_t* c,
		size_t len, uint8_t* m) {
	  aes_whitebox_encrypt_ctr(nonce, c, len, m);
	}

}; // class wbaes512


class wbaes_mgr
{
public:
	std::string aes_name; // aes512
	std::string table_keyname;
	int Nk = 0;
	int Nr = 0;
	bool table_loaded = false;

	wbaes512 a512;

	wbaes_mgr(const std::string& aesname, const std::string& pathtbl, const std::string& tablekeyname, bool verbose = false)
	{
		aes_name = aesname;
		table_keyname = tablekeyname;

	  	int Nk = 0, Nr = 0;
	  	if (strcmp(aes_name.data(), "aes128") == 0)
		{
			Nk = 4, Nr = 10;
		}
		else if (strcmp(aes_name.data(), "aes192") == 0)
		{
			Nk = 6, Nr = 12;
		}
		else if (strcmp(aes_name.data(), "aes256") == 0) {
			Nk = 8, Nr = 14;
		}
		else if (strcmp(aes_name.data(), "aes512") == 0) {
			Nk = 16, Nr = 22;
		}
		else if (strcmp(aes_name.data(), "aes1024") == 0) {
			Nk = 32, Nr = 38;
		}
		else if (strcmp(aes_name.data(), "aes2048") == 0) {
			Nk = 64, Nr = 70;
		}
		else if (strcmp(aes_name.data(), "aes4096") == 0) {
			Nk = 128, Nr = 134;
		}

		table_loaded = load_tables(pathtbl, verbose);
	}

	bool load_tables(const std::string& pathtbl, bool verbose = false)
	{
		bool r = true;
		if (aes_name == std::string("aes512"))
		{
			if (verbose) std::cout << "loading aes512... " << table_keyname << std::endl;
			{
				std::string filename = pathtbl + "aes512_" + table_keyname + "_xor.tbl";
				if (verbose) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					ifd >> bits(a512.Xor);
					ifd.close();
					if (verbose)
					{
						std::cout << "ok " << filename << std::endl;
						for (int r = 0; r < 2; r++) {
							std::cout << "  {\n";
							for (int n = 0; n < 5; n++) {
							  std::cout << "    {\n";
							  for (int i = 0; i < 2; i++) {
								std::cout << "      { ";
								for (int j = 0; j < 2; j++)
								  std::cout <<  (int)a512.Xor[r][n][i][j];
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
					ifd.close();
				}
			}

			if (r)
			{
				std::string filename = pathtbl + "aes512_" + table_keyname + "_tboxesLast.tbl";
				if (verbose) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					ifd >> bits(a512.TboxesLast);
					ifd.close();
					if (verbose) std::cout << "ok " << filename << std::endl;
				}
				else
				{
					std::cerr << "ERROR reading " << filename << std::endl;
					r = false;
					ifd.close();
				}
			}

			if (r)
			{
				std::string filename = pathtbl + "aes512_" + table_keyname + "_tyboxes.tbl";
				if (verbose) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					ifd >> bits(a512.Tyboxes);
					ifd.close();
					if (verbose) std::cout << "ok " << filename << std::endl;
				}
				else
				{
					std::cerr << "ERROR reading " << filename << std::endl;
					r = false;
					ifd.close();
				}
			}

			if (r)
			{
				std::string filename = pathtbl + "aes512_" + table_keyname + "_mbl.tbl";
				if (verbose) std::cout << "reading " << filename << std::endl;

				std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
				if (ifd.bad() == false)
				{
					ifd >> bits(a512.MBL);
					ifd.close();
					if (verbose) std::cout << "ok " << filename << std::endl;
				}
				else
				{
					std::cerr << "ERROR reading " << filename << std::endl;
					r = false;
					ifd.close();
				}
			}
		}
		return r;
	}
};

}  // namespace

#endif
#endif
#endif
