#ifndef _INCLUDES_aes_whitebox_compiler_HPP
#define _INCLUDES_aes_whitebox_compiler_HPP

#include "../../base_const.hpp"
#include "../../c_plus_plus_serializer.h"
//-lntl -lpthread -lgmp

#ifdef _WIN32
#else
#ifdef HAS_WHITEBOX_AES_FEATURE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <array>

#include <NTL/mat_GF2.h>
#include "aes_private.h"

namespace WBAES {

std::array< std::array< std::array< std::array<uint8_t, 16>, 16>, 96>, 21> aes512Xor;
std::array< std::array< std::array< uint32_t, 256>, 16>, 21> aes512Tyboxes;
std::array< std::array< uint8_t, 256>, 16> aes512TboxesLast;
std::array< std::array< std::array< uint32_t, 256>, 16>, 21> aes512MBL;


void err_quit(const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  strcat(buf, "\n");
  fputs(buf, stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}

void read_key(const char *in, uint8_t* key, size_t size) {
  if (strlen(in) != size << 1)
    err_quit("Invalid key (should be a valid %d-bits hexadecimal string)",
        (size == 16) ? 128 : ((size == 24) ? 192 : 256));
  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", key + i);
  }
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
    result = (result << 4) | (i0 << 3) | (i1 << 2) | (i2 << 1) | (i3 << 0);
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
void CalculateTboxes(const uint32_t roundKey[],
    uint8_t Tboxes[][16][256], int Nr) {
  for (int r = 0; r < Nr; r++) {
    for (int x = 0; x < 256; x++) {
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

void CalculateTyBoxes(uint32_t roundKey[],
    uint32_t Tyboxes[][16][256], uint8_t TboxesLast[16][256],
    uint32_t MBL[][16][256], bool enableL, bool enableMB, int Nr) {
  uint8_t Tboxes[Nr][16][256];
  uint8_t Ty[4][256][4];

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

  if (enableMB) {
    NTL::mat_GF2 MB[Nr-1][4];
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

  if (enableL) {
    NTL::mat_GF2 L[Nr-1][16];
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
}

void GenerateXorTable(FILE* out, int Nr)
{
  uint8_t Xor[Nr-1][96][16][16];
  for (int r = 0; r < Nr-1; r++)
    for (int n = 0; n < 96; n++)
      for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
		{
          Xor[r][n][i][j] = i ^ j;
		  aes512Xor[r][n][i][j] = Xor[r][n][i][j];
		}

  fprintf(out, "constexpr uint8_t Xor[%d][96][16][16] = {\n", Nr-1);
  for (int r = 0; r < Nr-1; r++) {
    fprintf(out, "  {\n");
    for (int n = 0; n < 96; n++) {
      fprintf(out, "    {\n");
      for (int i = 0; i < 16; i++) {
        fprintf(out, "      { ");
        for (int j = 0; j < 16; j++)
          fprintf(out, "0x%02x, ", Xor[r][n][i][j]);
        fprintf(out, "},\n");
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");
}

void GenerateEncryptingTables(FILE* out, uint32_t* roundKey, int Nr) {
  uint32_t Tyboxes[Nr-1][16][256];
  uint8_t TboxesLast[16][256];
  uint32_t MBL[Nr-1][16][256];

  CalculateTyBoxes(roundKey, Tyboxes, TboxesLast, MBL, true, true, Nr);

  	for (int r = 0; r < Nr-1; r++)
  	for (int i = 0; i < 16; i++)
  	for (int x = 0; x < 256; x++)
	{
	  aes512Tyboxes[r][i][x] = Tyboxes[r][i][x];
	}

  fprintf(out, "constexpr uint32_t Tyboxes[%d][16][256] = {\n", Nr-1);
  for (int r = 0; r < Nr-1; r++) {
    fprintf(out, "  {\n");
    for (int i = 0; i < 16; i++) {
      fprintf(out, "    {\n");
      for (int x = 0; x < 256; x++) {
        if ((x % 8) == 0) {
          fprintf(out, "      ");
        }
        fprintf(out, "0x%08x,", Tyboxes[r][i][x]);
        if (x > 0 && (x % 8) == 7) {
          fprintf(out, "\n");
        } else {
          fprintf(out, " ");
        }
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  	for (int i = 0; i < 16; i++)
  	for (int x = 0; x < 256; x++)
	{
        aes512TboxesLast[i][x] = TboxesLast[i][x];
	}

  fprintf(out, "constexpr uint8_t TboxesLast[16][256] = {\n");
  for (int i = 0; i < 16; i++) {
    fprintf(out, "  {\n");
    for (int x = 0; x < 256; x++) {
      if (x % 16 == 0) {
        fprintf(out, "    ");
      }
      fprintf(out, "0x%02x, ", TboxesLast[i][x]);
      if (x % 16 == 15) {
        fprintf(out, "\n");
      }
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

	for (int r = 0; r < Nr-1; r++)
  	for (int i = 0; i < 16; i++)
  	for (int x = 0; x < 256; x++)
	{
	  aes512MBL[r][i][x] = MBL[r][i][x];
	}

  fprintf(out, "constexpr uint32_t MBL[%d][16][256] = {\n", Nr-1);
  for (int r = 0; r < Nr-1; r++) {
    fprintf(out, "  {\n");
    for (int i = 0; i < 16; i++) {
      fprintf(out, "    {\n");
      for (int x = 0; x < 256; x++) {
        if ((x % 8) == 0) {
          fprintf(out, "      ");
        }
        fprintf(out, "0x%08x,", MBL[r][i][x]);
        if (x > 0 && (x % 8) == 7) {
          fprintf(out, "\n");
        } else {
          fprintf(out, " ");
        }
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");
}

void GenerateTables(const char* hexKey, int Nk, int Nr) {
  uint8_t key[Nk*4];
  uint32_t roundKey[(Nr+1)*4];

  read_key(hexKey, key, Nk*4);
  ExpandKeys(key, roundKey, Nk, Nr);

  FILE* out = fopen("aes_whitebox_tables.cc", "w");

  fprintf(out,
      "// This file is generated, do not edit.\n"
      "\n"
      "namespace {\n"
      "\n"
      "constexpr int Nr = %d;\n"
      "\n", Nr);

  GenerateXorTable(out, Nr);
  GenerateEncryptingTables(out, roundKey, Nr);

  fprintf(out, "}  // namespace");

  fflush(out);
  fclose(out);
}

void syntax() {
  err_quit("Syntax: aes_whitebox_gen <aes128|aes192|aes256> <hex-key>");
}


int gen_aes(const std::string& aes, const std::string& pathtbl, bool verbose = false)
{
	int r = 0;
	int Nk = 0, Nr = 0;
	if (aes == std::string("aes512"))
	{
        std::cout << "gen_aes " << aes << std::endl;

		Nk = 16;
		Nr = 22;
		char k[4*Nk*2+10] = "313deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
		GenerateTables(k, Nk, Nr);

		{
			std::string filename = pathtbl + "aes512_name1_xor.tbl";
			if (verbose) std::cout << "gen_aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				ofd << bits(aes512Xor);

				if (verbose)
				{
					std::cout << "ok " << filename << std::endl;
					for (int r = 0; r < 2; r++) {
						std::cout << "  {\n";
						for (int n = 0; n < 5; n++) {
						  std::cout << "    {\n";
						  for (int i = 0; i < 2; i++) {
							std::cout << "      { ";
							for (int j = 0; j < 16; j++)
							  std::cout <<  (int)aes512Xor[r][n][i][j];
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
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();

			if (verbose) std::cout << "reading " << filename << std::endl;
			std::array< std::array< std::array< std::array<uint8_t, 16>, 16>, 96>, 21> bXor;
			std::ifstream ifd(filename.data(), std::ios::in | std::ios::binary);
			if (ifd.bad() == false)
			{
				ifd >> bits(bXor);
			}
			else
			{
				r = -1;
				std::cerr << "ERROR reading " << filename << std::endl;
			}
			ifd.close();

			bool ok = true;
			for (int r = 0; r < Nr-1; r++)
			for (int n = 0; n < 96; n++)
			for (int i = 0; i < 16; i++)
			for (int j = 0; j < 16; j++)
			{
			  if (aes512Xor[r][n][i][j] != bXor[r][n][i][j])
			  {
					std::cerr << "ERROR not same  " << r << n << i << j << std::endl;
					ok = false;
					break;
			  }
			}
			if (verbose)  if (ok) std::cout << "same  "  << std::endl;
		}

		{
			std::string filename = pathtbl + "aes512_name1_tyboxes.tbl";
			if (verbose)  std::cout << "gen_aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				ofd << bits(aes512Tyboxes);
			}
			else
			{
				r = -1;
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();
		}
		{
			std::string filename = pathtbl + "aes512_name1_tboxesLast.tbl";
			if (verbose)  std::cout << "gen_aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				ofd << bits(aes512TboxesLast);
			}
			else
			{
				r = -1;
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();
		}
		{
			std::string filename = pathtbl + "aes512_name1_mbl.tbl";
			if (verbose)  std::cout << "gen_aes to " << filename << std::endl;

			std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
			if (ofd.bad() == false)
			{
				ofd << bits(aes512MBL);
			}
			else
			{
				r = -1;
				std::cerr << "ERROR writing " << filename << std::endl;
			}
			ofd.close();
		}
	}
	return r;
}

}  // namespace


#endif
#endif
#endif
