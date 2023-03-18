#ifndef __ECC__CURVE__
#define __ECC__CURVE__

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <gmpxx.h>
#include "../../Buffer.hpp"

// Point of an elliptic curve
typedef struct ecc_point
{
	mpz_t x;
    mpz_t y;
    bool is_valid = true;
    bool is_infinity = false;
} ecc_point;

struct message_point
{
	ecc_point p;
	int qtd_adicoes = 0; // msg point x = msg+qtd_adicoes
};

struct ecc_curve
{
    static constexpr int BASE_16 = 16; // 256 = "100" 65536="10000"

    unsigned int bits_len; // prime bits
    mpz_t a;
    mpz_t b;
    mpz_t prime;
    mpz_t order;
    int cofactor;
    ecc_point generator_point;
    unsigned int MSG_BYTES_MAX; // ONE BYTE for counter
    unsigned int MSG_BYTES_PAD = 1;
    bool verbose = false;

    int init_curve( unsigned int nbits,
                    const std::string& ia, const std::string& ib, const std::string& iprime, const std::string& iorder, int icofactor, const std::string& igx, const std::string& igy);

    ecc_point mult(ecc_point p, mpz_t value);
    ecc_point sum(ecc_point p1, ecc_point p2);

    int isPoint(ecc_point& p);
    ecc_point existPoint(mpz_t& x);
    int existPoint1(mpz_t& x, mpz_t& y);
    ecc_point double_p(ecc_point p);

	message_point  	getECCPointFromMessage(cryptoAL::Buffer& message);
    void 			getMessageFromPoint(message_point& msg_point, cryptoAL::Buffer& message);
    bool            format_msg_for_ecc(const std::string& msg, cryptoAL::Buffer& buffer_out);

    int  test_msg(const std::string& msg);
    bool test_encode_decode(const std::string& msg);

    bool encode(ecc_point& out_Cm, ecc_point& out_rG, const std::string& msg, ecc_point& publicKey, mpz_t& private_key);
    bool decode(ecc_point& in_Cm,  ecc_point& in_rG,  std::string&   out_msg, mpz_t& private_key);

    std::string pow256string(long n)
    {
        //"1", "100", "10000",
        std::string s = "1";
        if (n==0) return s;
        for(long i=0;i<n;i++)
        {
            s += "00";
        }
        return s;
    }

    unsigned int bitSize(const mpz_t &number)
    {
       return static_cast<unsigned int>(mpz_sizeinbase(number, 2));
    }
};

int mpz_sqrtm(mpz_t q, const mpz_t n, const mpz_t p);
int quadratic_residue(mpz_t x, mpz_t q,mpz_t n);
int test_tonelli(const std::string& sprime, const std::string& sa, mpz_t out_x);
int random_in_range (unsigned int min, unsigned int max);

#endif

