#ifndef _INCLUDES_aes_whitebox_compiler_HPP
#define _INCLUDES_aes_whitebox_compiler_HPP

#include "../../crypto_const.hpp"
#include "../../random_engine.hpp"
#include "../../data.hpp"
#include "../../c_plus_plus_serializer.h"

//Original code: https://github.com/balena/aes-whitebox
#ifdef _WIN32
//add preprocessor directive NOMINMAX
#pragma warning ( disable : 4146 )
#endif
#include <NTL/mat_GF2.h>
#include "aes_private.h"
#include "aes_whitebox.hpp"
//LINKER LIB: -lntl -lpthread -lgmp

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <array>

namespace WBAES
{

bool read_key(const char *in, uint8_t* key, size_t size)
{
	bool r = true;
  	if (strlen(in) != size << 1)
	{
		std::cerr << "ERROR invalid key size, need hexadecimal string of size " << (size << 1) << std::endl;
	}
	else
	{
		for (size_t i = 0; i < size; i++)
		{
			sscanf(in + i * 2, "%2hhx", key + i);
		}
	}
	return r;
}

template<typename T>
inline NTL::vec_GF2 from_scalar(T in);

template<>
inline NTL::vec_GF2 from_scalar(uint8_t in) {
  NTL::vec_GF2 result;
  result.SetLength(8);
  for (int i = 0; i < 8; i++) {
    result[7 - i] = ((in >> i) & 1);
  }
  return result;
}

template<>
inline NTL::vec_GF2 from_scalar(uint32_t in) {
  NTL::vec_GF2 result;
  result.SetLength(32);
  for (int i = 0; i < 32; i++) {
    result[31 - i] = ((in >> i) & 1);
  }
  return result;
}

template<typename T>
inline T to_scalar(const NTL::vec_GF2& in);

template<>
inline uint8_t to_scalar(const NTL::vec_GF2& in) {
  uint8_t result = 0;
  for (int i = 0; i < 2; i++) {
    long i0 = NTL::rep(in[i*4+0]), i1 = NTL::rep(in[i*4+1]),
         i2 = NTL::rep(in[i*4+2]), i3 = NTL::rep(in[i*4+3]);
    result = (uint8_t) ( (result << 4) | (i0 << 3) | (i1 << 2) | (i2 << 1) | (i3 << 0) );
  }
  return result;
}

template<>
inline uint32_t to_scalar(const NTL::vec_GF2& in) {
  uint32_t result = 0;
  for (int i = 0; i < 8; i++) {
    long i0 = NTL::rep(in[i*4+0]), i1 = NTL::rep(in[i*4+1]),
         i2 = NTL::rep(in[i*4+2]), i3 = NTL::rep(in[i*4+3]);
    result = (result << 4) | (i0 << 3) | (i1 << 2) | (i2 << 1) | (i3 << 0);
  }
  return result;
}

template<typename T>
inline T mul(const NTL::mat_GF2& mat, T x) {
  return to_scalar<T>(mat * from_scalar<T>(x));
}

NTL::mat_GF2 GenerateGF2RandomMatrix(int dimension) {
  NTL::mat_GF2 mat(NTL::INIT_SIZE, dimension, dimension);
  for (int i = 0; i < dimension; i++) {
    for (int j = 0; j < dimension; j++) {
      mat[i][j] = NTL::random_GF2();
    }
  }
  return mat;
}

NTL::mat_GF2 GenerateRandomGF2InvertibleMatrix(int dimension) {
  for (;;) {
    NTL::mat_GF2 result = GenerateGF2RandomMatrix(dimension);
    if (NTL::determinant(result) != 0)
      return result;
  }
}

// Calculate the T-boxes, which is a combination of the AddRoundKeyAfterShift
// and the SubBytes functions.
void CalculateTboxes(   const uint32_t roundKey[],
                        std::vector<std::vector<std::vector<uint8_t>>>& Tboxes,
                        int Nr)
{
  for (int r = 0; r < Nr; r++)
  {
    for (int x = 0; x < 256; x++)
     {
      uint8_t state[16] = {
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x
      };
      AddRoundKeyAfterShift(state, &roundKey[r*4]);
      SubBytes(state);
      if (r == Nr-1) {
        AddRoundKey(state, &roundKey[4*Nr]);
      }
      for (int i = 0; i < 16; i++) {
        Tboxes[r][i][x] = state[i];
      }
    }
  }
}

void CalculateTy(uint8_t Ty[4][256][4]) {
  for (int x = 0; x < 256; x++) {
    Ty[0][x][0] = gf_mul[x][0];
    Ty[0][x][1] = gf_mul[x][1];
    Ty[0][x][2] = x;
    Ty[0][x][3] = x;

    Ty[1][x][0] = x;
    Ty[1][x][1] = gf_mul[x][0];
    Ty[1][x][2] = gf_mul[x][1];
    Ty[1][x][3] = x;

    Ty[2][x][0] = x;
    Ty[2][x][1] = x;
    Ty[2][x][2] = gf_mul[x][0];
    Ty[2][x][3] = gf_mul[x][1];

    Ty[3][x][0] = gf_mul[x][1];
    Ty[3][x][1] = x;
    Ty[3][x][2] = x;
    Ty[3][x][3] = gf_mul[x][0];
  }
}

void CalculateTyBoxes(	uint32_t roundKey[],
						std::vector<std::vector<std::vector<uint32_t>>>& Tyboxes, 	//uint32_t Tyboxes[][16][256],
						uint8_t TboxesLast[16][256],
						std::vector<std::vector<std::vector<uint32_t>>>& MBL, 		//uint32_t MBL[][16][256],
						bool enableL,
						bool enableMB, int Nr)
{
    uint8_t Ty[4][256][4];

    //uint8_t Tboxes[Nr][16][256];
	std::vector<std::vector<std::vector<uint8_t>>>* pTboxes = new std::vector<std::vector<std::vector<uint8_t>>>(Nr);
	std::vector<std::vector<std::vector<uint8_t>>>& Tboxes = *pTboxes;
	for(int i=0;i<Nr;i++)
	{
        Tboxes[i].resize(16);
        for(int j=0;j<16;j++)
            Tboxes[i][j].resize(256);
	}

    CalculateTboxes(roundKey, Tboxes, Nr);
    CalculateTy(Ty);

    for (int r = 0; r < Nr-1; r++) {
    for (int x = 0; x < 256; x++) {
      for (int j = 0; j < 4; j++) {
        for (int i = 0; i < 4; i++) {
          uint32_t v0 = Ty[0][Tboxes[r][j*4 + i][x]][i],
                   v1 = Ty[1][Tboxes[r][j*4 + i][x]][i],
                   v2 = Ty[2][Tboxes[r][j*4 + i][x]][i],
                   v3 = Ty[3][Tboxes[r][j*4 + i][x]][i];
          Tyboxes[r][j*4 + i][x] = (v0 << 24) | (v1 << 16) | (v2 << 8) | v3;
          MBL[r][j*4 + i][x] = x << ((3 - i) << 3);
        }
      }
    }
  }

  for (int x = 0; x < 256; x++) {
    for (int i = 0; i < 16; i++) {
      TboxesLast[i][x] = Tboxes[Nr-1][i][x];
    }
  }

  //NTL::mat_GF2 MB[Nr-1][4];
  std::vector< std::vector<NTL::mat_GF2> >* pMB = new std::vector<std::vector<NTL::mat_GF2 >>(Nr - 1);
  if (enableMB)
  {
	  std::vector< std::vector<NTL::mat_GF2> >& MB = *pMB;
	  for (int i = 0; i < Nr-1; i++)
	  {
		  MB[i].resize(4);
	  }

    for (int r = 0; r < Nr-1; r++) {
      for (int i = 0; i < 4; i++) {
        MB[r][i] = GenerateRandomGF2InvertibleMatrix(32);
      }
    }

    // When applying MB and inv(MB), the operation is quite easy; there is no
    // need to safeguard the existing table, as it is a simple substitution.
    for (int r = 0; r < Nr-1; r++) {
      for (int x = 0; x < 256; x++) {
        for (int i = 0; i < 16; i++) {
          Tyboxes[r][i][x] = mul<uint32_t>(MB[r][i >> 2], Tyboxes[r][i][x]);
          MBL[r][i][x] = mul<uint32_t>(NTL::inv(MB[r][i >> 2]), MBL[r][i][x]);
        }
      }
    }
  }

  //NTL::mat_GF2 L[Nr-1][16];
  std::vector< std::vector<NTL::mat_GF2> >* pL = new std::vector<std::vector<NTL::mat_GF2 >>(Nr - 1);
  if (enableL)
  {
	std::vector< std::vector<NTL::mat_GF2> >& L = *pL;
	for (int i = 0; i < Nr - 1; i++)
	{
		L[i].resize(16);
	}

    for (int r = 0; r < Nr-1; r++) {
      for (int i = 0; i < 16; i++) {
        L[r][i] = GenerateRandomGF2InvertibleMatrix(8);
      }
    }

    // When applying L and inv(L), things get a little tricky. As it involves
    // non-linear substitutions, the original table has to be copied before
    // being updated.
    for (int r = 0; r < Nr-1; r++) {

      if (r > 0) {
        // Rounds 1 to Nr-1 are reversed here.
        for (int i = 0; i < 16; i++) {
          uint32_t oldTyboxes[256];
          for (int x = 0; x < 256; x++)
            oldTyboxes[x] = Tyboxes[r][i][x];
          for (int x = 0; x < 256; x++)
            Tyboxes[r][i][x] = oldTyboxes[mul<uint8_t>(NTL::inv(L[r-1][i]), x)];
        }
      }

      // Apply the L transformation at each round.
      for (int j = 0; j < 4; ++j) {
        for (int x = 0; x < 256; x++) {
          uint32_t out0 = MBL[r][j*4 + 0][x];
          uint32_t out1 = MBL[r][j*4 + 1][x];
          uint32_t out2 = MBL[r][j*4 + 2][x];
          uint32_t out3 = MBL[r][j*4 + 3][x];

          MBL[r][j*4 + 0][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 0]], out0 >> 24) << 24)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 1]], out0 >> 16) << 16)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 2]], out0 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 3]], out0 >>  0) <<  0);

          MBL[r][j*4 + 1][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 0]], out1 >> 24) << 24)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 1]], out1 >> 16) << 16)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 2]], out1 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 3]], out1 >>  0) <<  0);

          MBL[r][j*4 + 2][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 0]], out2 >> 24) << 24)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 1]], out2 >> 16) << 16)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 2]], out2 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 3]], out2 >>  0) <<  0);

          MBL[r][j*4 + 3][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 0]], out3 >> 24) << 24)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 1]], out3 >> 16) << 16)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 2]], out3 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][InvShiftRowsTab[j*4 + 3]], out3 >>  0) <<  0);
        }
      }
    }

    // The last and final round 9 is reversed here.
    for (int i = 0; i < 16; i++) {
      uint8_t oldTboxesLast[256];
      for (int x = 0; x < 256; x++)
        oldTboxesLast[x] = TboxesLast[i][x];
      for (int x = 0; x < 256; x++)
        TboxesLast[i][x] = oldTboxesLast[mul<uint8_t>(NTL::inv(L[Nr-2][i]), x)];
    }
  }

  delete pTboxes;

  if (enableMB) delete pMB;
  if (enableL) delete pL;
}

void GenerateXorTable(const char* rndKey, uint32_t rndsize, int Nr, wbaes_vbase* instance_aes,  [[maybe_unused]] bool verbose = false)
{
    if (cryptoAL::VERBOSE_DEBUG) std::cout << "GenerateXorTable..." << std::endl;

  	//uint8_t Xor[Nr-1][96][16][16];
    std::vector<std::vector<std::vector<std::vector<uint8_t>>>>* pXor = new std::vector<std::vector<std::vector<std::vector<uint8_t>>>>(Nr-1);
	std::vector<std::vector<std::vector<std::vector<uint8_t>>>>& Xor = *pXor;
	for(int i=0;i<Nr-1;i++)
	{
        Xor[i].resize(96);
        for(int j=0;j<96;j++)
        {
            Xor[i][j].resize(16);
            for(int k=0;k<16;k++)
                Xor[i][j][k].resize(16);
        }
	}

	if (cryptoAL::VERBOSE_DEBUG) std::cout << "GenerateEncryptingTables..." << std::endl;
	uint32_t idx = 0; char a; char b;
  	for (int r = 0; r < Nr-1; r++)
    for (int n = 0; n < 96; n++)
      for (int i = 0; i < 16; i++)
	  {
        for (int j = 0; j < 16; j++)
		{
			// EXTERNAL ENCODING here - default to random
          	// Xor[r][n][i][j] = i ^ j;
			a = rndKey[idx % rndsize];
			b = rndKey[(idx+1) % rndsize];
			Xor[r][n][i][j] = (uint8_t)( ((uint8_t)a) + 16*((uint8_t)b) );
			idx+=2;
		  	instance_aes->setXor(r, n, j, i, Xor[r][n][i][j]);
		}
	}
	if (cryptoAL::VERBOSE_DEBUG) std::cout << "GenerateXorTable done" << std::endl;

    delete pXor;
}

void GenerateEncryptingTables(uint32_t* roundKey, int Nr, wbaes_vbase* instance_aes,  [[maybe_unused]] bool verbose = false)
{
    if (cryptoAL::VERBOSE_DEBUG) std::cout << "GenerateEncryptingTables..." << std::endl;
    uint8_t TboxesLast[16][256];

	//uint32_t Tyboxes[Nr-1][16][256];
    std::vector<std::vector<std::vector<uint32_t>>>* pTyboxes = new std::vector<std::vector<std::vector<uint32_t>>>(Nr-1);
	std::vector<std::vector<std::vector<uint32_t>>>& Tyboxes = *pTyboxes;
	for(int i=0;i<Nr-1;i++)
	{
        Tyboxes[i].resize(16);
        for(int j=0;j<16;j++)
            Tyboxes[i][j].resize(256);
	}

	//uint32_t MBL[Nr-1][16][256];
    std::vector<std::vector<std::vector<uint32_t>>>* pMBL = new std::vector<std::vector<std::vector<uint32_t>>>(Nr-1);
	std::vector<std::vector<std::vector<uint32_t>>>& MBL = *pMBL;
	for(int i=0;i<Nr-1;i++)
	{
        MBL[i].resize(16);
        for(int j=0;j<16;j++)
            MBL[i][j].resize(256);
	}


    // all stack variable! moving them to heap...
  	CalculateTyBoxes(roundKey, Tyboxes, TboxesLast, MBL, true, true, Nr);

  	for (int r = 0; r < Nr-1; r++)
  	for (int i = 0; i < 16; i++)
  	for (int x = 0; x < 256; x++)
	{
	  	instance_aes->setTyboxes(r, i, x, Tyboxes[r][i][x]);
	}

  	for (int i = 0; i < 16; i++)
  	for (int x = 0; x < 256; x++)
	{
        instance_aes->setTboxesLast(i,x,TboxesLast[i][x]);
	}

	for (int r = 0; r < Nr-1; r++)
  	for (int i = 0; i < 16; i++)
  	for (int x = 0; x < 256; x++)
	{
	  	instance_aes->setMBL(r,i,x, MBL[r][i][x]);
	}

	delete pTyboxes ;
	delete pMBL;
}

bool GenerateTables(const char* hexKey, const char* rndKey, uint32_t rndsize, int Nk, int Nr, wbaes_vbase* instance_aes, bool verbose = false)
{
	bool r  = true;
  	//uint8_t key[Nk*4];
	std::vector<uint8_t>* pkey = new std::vector<uint8_t>(Nk * 4);
	std::vector<uint8_t>& key = *pkey;

  	//uint32_t roundKey[(Nr+1)*4];
	std::vector<uint32_t>* proundKey = new std::vector<uint32_t>( (Nr + 1) * 4 );
	std::vector<uint32_t>& roundKey = *proundKey;

  	r = read_key(hexKey, key.data(), Nk * 4);
  	if (r)
  	{
  		if (verbose) std::cout << "GenerateTables..." << std::endl;
	  	ExpandKeys(key.data(), roundKey.data(), Nk, Nr, verbose);
	  	GenerateXorTable(rndKey, rndsize, Nr, instance_aes, verbose);
	  	GenerateEncryptingTables(roundKey.data(), Nr, instance_aes, verbose);
  	}
	return r;
}


int generate_aes(	const std::string& short_file_for_key,
					const std::string& short_file_for_xor,
					const std::string& file_for_key, uint32_t pos1,
					const std::string& file_for_xor, uint32_t pos2,
					const std::string& aes,
					const std::string& pathtbl,
					const std::string& tablekeyname,
					bool gen_build_info = true,
					bool verbose = false)
{
	if (file_util::fileexists(file_for_key) == false)
	{
		std::cerr << "ERROR missing file for key: " << file_for_key <<  std::endl;
		return -1;
	}
	if (file_util::fileexists(file_for_xor) == false)
	{
		std::cerr << "ERROR missing file for xor: " << file_for_xor <<  std::endl;
		return -1;
	}

	cryptoAL::cryptodata data_file_for_key;
	bool rr = data_file_for_key.read_from_file(file_for_key);
	auto sz = data_file_for_key.buffer.size();
	if (rr == false)
	{
		std::cerr << "ERROR reading file for key " <<  " file: " << file_for_key << std::endl;
		return -1;
	}

	cryptoAL::cryptodata data_file_for_xor;
	rr = data_file_for_xor.read_from_file(file_for_xor);
	if (rr == false)
	{
		std::cerr << "ERROR reading file for xor " <<  " file: " << file_for_xor << std::endl;
		return -1;
	}

	//-----------------------------------------------------
	// build_info
	//-----------------------------------------------------
	if (gen_build_info)
	{
        cryptoAL::cryptodata build_info_file;
        std::string build_info_filename = pathtbl + aes + "_" + tablekeyname + "_build_info" + ".tbl";
        std::string s_build_info;
        s_build_info += std::string("aes: ") + aes + "\n";
        s_build_info += std::string("key: ") + tablekeyname 			+ "\n";
        s_build_info += std::string("filekey: ") + short_file_for_key 	+ "\n";
        s_build_info += std::string("pos_filekey: ") + std::to_string(pos1) + "\n";
        s_build_info += std::string("filexor: ") + short_file_for_xor 	+ "\n";
        s_build_info += std::string("pos_filexor: ") + std::to_string(pos2) + "\n";
        {
            std::string sha = file_util::file_checksum(file_for_key);
            s_build_info += std::string("sha_filekey: ") + sha + "\n";
        }
        {
            std::string sha = file_util::file_checksum(file_for_xor);
            s_build_info += std::string("sha_filexor: ") + sha + "\n";
        }
        s_build_info += "\n";
        build_info_file.buffer.write(s_build_info.data(), (uint32_t)s_build_info.size());
        rr = build_info_file.save_to_file(build_info_filename);
        if (rr == false)
        {
            std::cerr << "ERROR writing build info file " << build_info_filename << std::endl;
            return -1;
        }
        if (verbose)
            std::cout << "build info will be at: " << build_info_filename << std::endl;
    }

	int r = 0;
	bool ok = true;
	int Nk = 0, Nr = 0;
	if (aes == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes512) )
	{
		Nk = 16, Nr = 22;
	}
	else if (aes == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes1024) )
	{
		Nk = 32, Nr = 38;
	}
	else if (aes == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes2048) )
	{
		Nk = 64, Nr = 70;
	}
	else if (aes == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes4096) )
	{
		Nk = 128, Nr = 134;
	}
	else if (aes == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes8192) )
	{
		Nk = 128*2, Nr = 134*2 - 6;
	}
	else if (aes == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes16384) )
	{
		Nk = 512, Nr = 526;
	}
	else if (aes == algo_wbaes_name(cryptoAL::CRYPTO_ALGO::ALGO_wbaes32768) )
	{
		Nk = 1024, Nr = 1038;
	}
	else if (strcmp(aes.data(), "aes128") == 0)
	{
		Nk = 4, Nr = 10;
	}
	else if (strcmp(aes.data(), "aes192") == 0)
	{
		Nk = 6, Nr = 12;
	}
	else if (strcmp(aes.data(), "aes256") == 0) {
		Nk = 8, Nr = 14;
	}
	else
	{
		// TODO
	}

	// TODO - merge tbl
	{
        if (verbose) std::cout << "generating whitebox aes... " << aes << std::endl;

		long long N = 4*Nk*2;

		if (sz < N+pos1)
		{
            std::cerr << "ERROR file for key less than required key length " << N+pos1 << std::endl;
            return -1;
		}

		if (data_file_for_xor.buffer.size() <=  pos2 + N)
		{
		    std::cerr << "ERROR file for xor too small given he provided position  " << pos2 + N << std::endl;
            return -1;
		}

		int n;
		int digit;
		std::string skey;
		for(long long i=pos1;i<pos1+N;i++)
        {
			n = (int)(unsigned char)data_file_for_key.buffer.getdata()[i];
            digit = (int)(n % 16);
            if ((i==0) && (cryptoAL::BASEDIGIT16[digit]=='0'))
			{
				digit = 1;
			}
            skey += cryptoAL::BASEDIGIT16[digit];
        }
		if (verbose) std::cout << "key " << skey << std::endl;

		WBAES::wbaes_instance_mgr aes_instance(aes, pathtbl, tablekeyname, false, true);
		WBAES::wbaes_vbase* p = aes_instance.get_aes(); // new
		if (p==nullptr)
		{
            std::cerr << "ERROR in  aes_instance.get_aes() " << std::endl;
            return -1;
		}

		ok = GenerateTables(skey.data(), &data_file_for_xor.buffer.getdata()[pos2], data_file_for_xor.buffer.size() - pos2, Nk, Nr, p, verbose);

		if (ok)
		 {
			std::string filename = pathtbl + aes + "_" + tablekeyname + "_xor.tbl";
			if (cryptoAL::VERBOSE_DEBUG) std::cout << "generate aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				p->write_xor(ofd);

				int cnt_zero=0;
				int cnt=0;
				{
					for (int r = 0; r < 2; r++)
					{
						for (int n = 0; n < 5; n++)
						{
						  for (int i = 0; i < 2; i++)
						  {
							for (int j = 0; j < 16; j++)
							{
								if (p->getXor(r,n,i,j) == 0) cnt_zero++;
								cnt++;
							}
						  }
						}
					}
					if (cnt_zero == cnt)
					{
						r = -1;
						ok = false;
						std::cerr << "ERROR aes xor table seem empty " << filename << std::endl;
					}
				}

				if (cryptoAL::VERBOSE_DEBUG)
				{
					std::cout << "ok " << filename << std::endl;
					for (int r = 0; r < 2; r++) {
						std::cout << "  {\n";
						for (int n = 0; n < 5; n++) {
						  std::cout << "    {\n";
						  for (int i = 0; i < 2; i++) {
							std::cout << "      { ";
							for (int j = 0; j < 16; j++)
							{
								std::cout <<  (int)p->getXor(r,n,i,j); //  [r][n][i][j];
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
				r = -1;
				ok = false;
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();
		}
		else
		{
            std::cerr << "ERROR in GenerateTables " << std::endl;
		}

		if (ok)
		{
			std::string filename = pathtbl + aes + "_" + tablekeyname + "_tyboxes.tbl";
			if (cryptoAL::VERBOSE_DEBUG)  std::cout << "generate aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				p->write_tyboxes(ofd);
			}
			else
			{
				r = -1;
				ok = false;
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();
		}

		if (ok)
		{
			std::string filename = pathtbl + aes + "_" + tablekeyname + "_tboxesLast.tbl";
			if (cryptoAL::VERBOSE_DEBUG)  std::cout << "generate aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				p->write_tboxesLast(ofd);
			}
			else
			{
				r = -1;
				ok = false;
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();
		}

		if (ok)
		{
			std::string filename = pathtbl + aes + "_" + tablekeyname + "_mbl.tbl";
			if (cryptoAL::VERBOSE_DEBUG)  std::cout << "generate aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				p->write_mbl(ofd);
			}
			else
			{
				r = -1;
				ok = false;
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();
		}
	}
	return r;
}

}  // namespace

#endif

