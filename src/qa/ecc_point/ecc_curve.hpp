#ifndef __ECC__CURVE__
#define __ECC__CURVE__

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <gmpxx.h>

// Point of an elliptic curve
typedef struct ecc_point
{
	mpz_t x;
    mpz_t y;
    bool is_valid = true;
    bool is_infinity = false;
} ecc_point;

typedef struct message_point
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
    unsigned int MSG_BYTES_MAX; // ONE BYTE LESS

    int init_curve(char* a, char* b, char* prime, char* order, int cofactor, ecc_point g);

    ecc_point mult(ecc_point p, mpz_t value);
    ecc_point sum(ecc_point p1, ecc_point p2);

    int isPoint(ecc_point& p);
    ecc_point existPoint(mpz_t& x);
    int existPoint1(mpz_t& x, mpz_t& y);
    ecc_point double_p(ecc_point p);

    int quadratic_residue(mpz_t x, mpz_t q,mpz_t n);
    int random_in_range (unsigned int min, unsigned int max);

    message_point  getECCPointFromMessage(char* message);
    char*          getMessageFromPoint(message_point& msg);

    int test();
    int test_functions();


//  const char* pot_256[21] = {  "1", "100", "10000", "1000000", "100000000", "10000000000", "1000000000000", "100000000000000",
    std::string pow256string(long n)
    {
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

#endif

