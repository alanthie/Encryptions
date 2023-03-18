#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <climits>
#include <random>
#include <chrono>
#include <iostream>
#include <gmpxx.h>

int legendre_symbol(const mpz_t a, const mpz_t p) {
	mpz_t top;
	mpz_init_set(top, a);
	mpz_t bottom;
	mpz_init_set(bottom, p);
	mpz_t i;
	mpz_init(i);
	int result = 1;
	while (true) {
		if (mpz_cmp_si(top, 1) == 0) { // top == 1
			mpz_clear(i);
			mpz_clear(top);
			mpz_clear(bottom);
			return result;
		}
		else if (mpz_cmp_si(top, 2) == 0) { // top == 2
			mpz_set_si(i, 8);
			mpz_mod(i, bottom, i);
			if (mpz_cmp_si(i, 1) != 0 && mpz_cmp_si(i, 7) != 0) // i % 8 != 1 && i % 8 != 7
				result *= -1;
			mpz_clear(i);
			mpz_clear(top);
			mpz_clear(bottom);
			return result;
		}
		else if (mpz_cmp_si(top, 3) == 0 && mpz_cmp_si(bottom, 3) != 0) { // top == 3 && bottom != 3
			mpz_set_si(i, 12);
			mpz_mod(i, bottom, i);
			if (mpz_cmp_si(i, 1) == 0 || mpz_cmp_si(i, 11) == 0) {// i % 12 == 1 || i % 12 == 11
				mpz_clear(i);
				mpz_clear(top);
				mpz_clear(bottom);
				return result;
			}
			if (mpz_cmp_si(i, 5) == 0 || mpz_cmp_si(i, 7) == 0) {// i % 12 == 5 || i % 12 == 7
				mpz_clear(i);
				mpz_clear(top);
				mpz_clear(bottom);
				return -result;
			}
		}
		else if (mpz_cmp_si(top, 5) == 0 && mpz_cmp_si(bottom, 5) != 0) { // top == 5 && bottom != 5
			mpz_set_si(i, 5);
			mpz_mod(i, bottom, i);
			if (mpz_cmp_si(i, 1) != 0 && mpz_cmp_si(i, 4) != 0) // i % 5 != 1 && i % 5 != 4
				result *= -1;
			mpz_clear(i);
			mpz_clear(top);
			mpz_clear(bottom);
			return result;
		}
		mpz_mod(top, top, bottom); // top = top % bottom
		mpz_set_si(i, 1);
		mpz_and(i, top, i); // i = top & 1
		if (mpz_cmp_si(i, 1) == 0) { // top is odd
			mpz_set_si(i, 4);
			mpz_mod(i, top, i); // i = top % 4
			if (mpz_cmp_si(i, 3) == 0) {
				mpz_set_si(i, 4);
				mpz_mod(i, bottom, i); // i = bottom % 4
				if (mpz_cmp_si(i, 3) == 0)
					result *= -1;
			}
			mpz_set(i, top); // switch top and bottom
			mpz_set(top, bottom);
			mpz_set(bottom, i);
			mpz_mod(top, top, bottom);
		}
		mpz_set_si(i, 1);
		mpz_and(i, top, i);
		if (mpz_cmp_si(i, 0) == 0) { // top is even
			mpz_tdiv_q_2exp(top, top, 1); // top = top >> 1
			mpz_set_si(i, 2);
			result *= legendre_symbol(i, bottom);
		}
	}
}

void fast_exp_mod(mpz_t result, const mpz_t a, const mpz_t exp, const mpz_t p) {
	mpz_t exponent;
	mpz_init_set(exponent, exp);
	mpz_t base;
	mpz_init_set(base, a);
	mpz_set_si(result, 1);
	mpz_t comp;
	mpz_init(comp);
	mpz_t one;
	mpz_init_set_si(one, 1);
	while (mpz_cmp_si(exponent, 0) > 0) { // exponent > 0
		mpz_and(comp, exponent, one);
		if (mpz_cmp_si(comp, 1) == 0) { // exponent & 1 == 0
			mpz_mul(result, base, result);
			mpz_mod(result, result, p); // result = (base * result) % p
		}
		mpz_tdiv_q_2exp(exponent, exponent, 1); //exponent = exponent >> 1
		mpz_mul(base, base, base);
		mpz_mod(base, base, p); // base = (base * base) % p
	}
	mpz_clear(exponent);
	mpz_clear(base);
	mpz_clear(one);
	mpz_clear(comp);
}

bool miller_rabin(const mpz_t s, const mpz_t m, const mpz_t p) {
	if (mpz_cmp_si(p, 3) == 0) // p == 3
		return true;
	std::random_device rand_dev;
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, rand_dev());
	mpz_t a;
	mpz_init(a);
	mpz_t b;
	mpz_init(b);

	mpz_t max;
	mpz_init(max);
	mpz_sub_ui(max, p, 2); // max = p - 2

	mpz_t p_min_1;
	mpz_init(p_min_1);
	mpz_sub_ui(p_min_1, p, 1);

	mpz_t j;
	mpz_init(j);
	mpz_t j_fin;
	mpz_init_set(j_fin, s);
	mpz_sub_ui(j_fin, j_fin, 1); // j_fin = s - 1

	for (int i = 0; i < 5; ++i) {	//less than 1% chance of false positive
		while (true) {
			mpz_urandomm(a, state, max); // a = random number in [0, p - 2]
			if (mpz_cmp_si(a, 2) >= 0) //try again if a < 2
				break;
		}
		fast_exp_mod(b, a, m, p);
		bool prob_prime = false;
		if (mpz_cmp_si(b, 1) != 0 && mpz_cmp(b, p_min_1) != 0) { // b != 1 && b != p - 1
			mpz_set_si(j, 0);
			while (mpz_cmp(j, j_fin) < 0) {
				mpz_mul(b, b, b);
				mpz_mod(b, b, p); // b = (b * b) % p
				if (mpz_cmp_si(b, 1) == 0) { // b == 1
					mpz_clear(a);
					mpz_clear(b);
					mpz_clear(max);
					mpz_clear(p_min_1);
					mpz_clear(j);
					mpz_clear(j_fin);
					return false;
				}
				if (mpz_cmp(b, p_min_1) == 0) { // b == p - 1
					prob_prime = true;
					break;
				}
				mpz_add_ui(j, j, 1); // j++
			}
			if (!prob_prime) {
				mpz_clear(a);
				mpz_clear(b);
				mpz_clear(max);
				mpz_clear(p_min_1);
				mpz_clear(j);
				mpz_clear(j_fin);
				return false;
			}
		}
	}
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(max);
	mpz_clear(p_min_1);
	mpz_clear(j);
	mpz_clear(j_fin);
	return true;
}

int test_tonelli(const std::string& sprime, const std::string& sa, mpz_t out_x)
{
//	if (argc != 3) {
//		printf("Wrong number of arguments!\nRun program to solve for x in x^2 = a mod p:\n./tonelli_shanks <a> <p>\n");
//		exit(-1);
//	}
    mpz_init_set_str(out_x, "0", 10);

	mpz_t p;
	mpz_init_set_str(p, sprime.data(), 10);
	if (mpz_cmp_si(p, 3) < 0) {	// p < 3
		mpz_out_str(stdout, 10, p);
		printf(" is not greater than 2 or is non-numeric!\n");
		mpz_clear(p);
		return (-1);
	}
	mpz_t a;
	mpz_init_set_ui(a, 1);
	mpz_and(a, p, a);
	if (mpz_cmp_si(a, 1) != 0) { // p & 1 == 1
		mpz_out_str(stdout, 10, p);
		printf(" is not odd!\n");
		mpz_clear(p);
		mpz_clear(a);
		return (-1);
	}
	mpz_set_str(a, sa.data(), 10);
	if ((mpz_cmp_si(a, 0) == 0 && !strcmp(sa.data(), "0")) || (mpz_cmp_si(a, 0) == -1 && !strcmp(sa.data(), "-1"))) {
		mpz_out_str(stdout, 10, a);
		printf(" is non-numeric!\n");
		mpz_clear(p);
		mpz_clear(a);
		return (-1);
	}
	mpz_mod(a, a, p);
	if (a == 0) {
		printf("Solultion:  x = %d mod ", 0);
		mpz_out_str(stdout, 10, p);
		printf("\n");
		mpz_clear(p);
		mpz_clear(a);
	}


	mpz_t m;
	mpz_init(m);
	mpz_sub_ui(m, p, 1);
	mpz_tdiv_q_2exp(m, m, 1); // m = (p - 1) >> 2

	mpz_t s;
	mpz_init_set_ui(s, 1);
	mpz_t i;
	mpz_init(i);
	while (true) {
		mpz_set_si(i, 1);
		mpz_and(i, m, i);
		if (mpz_cmp_si(i, 1) == 0) // m & 1 == 1
			break;
		mpz_tdiv_q_2exp(m, m, 1); // m = m >> 1
		mpz_add_ui(s, s, 1); // s = s + 1
	}
	if (legendre_symbol(a, p) != 1) {
		mpz_out_str(stdout, 10, a);
		printf(" is not a quadratic residue of ");
		mpz_out_str(stdout, 10, p);
		printf("\n");
		mpz_clear(i);
		mpz_clear(p);
		mpz_clear(a);
		mpz_clear(m);
		mpz_clear(s);
		return(-1);
	}
	if (!miller_rabin(s, m, p)) {
		mpz_out_str(stdout, 10, p);
		printf(" is not a prime number\n");
		mpz_clear(i);
		mpz_clear(p);
		mpz_clear(a);
		mpz_clear(m);
		mpz_clear(s);
		return(-1);
	}

	printf("\nEquation:  x^2 = ");
	mpz_out_str(stdout, 10, a);
	printf(" mod ");
	mpz_out_str(stdout, 10, p);
	printf("\n\n");

	//return(1);

	auto begin = std::chrono::high_resolution_clock::now();
	if (mpz_cmp_si(s, 1) == 0) { // Case: p % 4 = 3
		mpz_add_ui(i, p, 1);
		mpz_tdiv_q_2exp(i, i, 2); // i = p - 1 >> 2
		fast_exp_mod(i, a, i, p);
		auto finish = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::microseconds>(finish - begin).count();
		printf("Solution:  x = ");
		mpz_out_str(stdout, 10, i);

		mpz_set(out_x, i);

		printf(" mod ");
		mpz_out_str(stdout, 10, p);
		printf("\n");

		mpz_sub(i, p, i); // i = p - i
		printf("           x = ");
		mpz_out_str(stdout, 10, i);

		//mpz_set(out_x, i);

		printf(" mod ");
		mpz_out_str(stdout, 10, p);
		printf("\n");
		std::cout << "\nRunning Time: " << duration << " us" << std::endl;
		mpz_clear(i);
		mpz_clear(p);
		mpz_clear(a);
		mpz_clear(m);
		mpz_clear(s);
		return (1);
	}

	mpz_t z;
	mpz_init_set_si(z, 2);
	while (legendre_symbol(z, p) != -1)
		mpz_add_ui(z, z, 1);

	mpz_t e;
	mpz_init_set(e, s);

	mpz_t c;
	mpz_init(c);
	fast_exp_mod(c, z, m, p);

	mpz_t x;
	mpz_init(x);
	mpz_add_ui(i, m, 1);
	mpz_tdiv_q_2exp(i, i, 1);
	fast_exp_mod(x, a, i, p);

	mpz_t t;
	mpz_init(t);
	fast_exp_mod(t, a, m, p);

	mpz_t temp;
	mpz_init(temp);
	mpz_t b;
	mpz_init(b);

	while(mpz_cmp_si(t, 1) != 0) {
		mpz_set_si(i, 1);
		while (true) {
			mpz_set_si(temp, 2);
			mpz_pow_ui(temp, temp, mpz_get_ui(i));
			fast_exp_mod(temp, t, temp, p);
			if (mpz_cmp_si(temp, 1) == 0)
				break;
			mpz_add_ui(i, i, 1);
		}
		mpz_sub(temp, e, i);
		mpz_sub_ui(temp, temp, 1);
		mpz_ui_pow_ui (temp, 2, mpz_get_ui(temp));
		fast_exp_mod(b, c, temp, p);
		mpz_mul(x, b, x);
		mpz_mod(x, x, p);
		mpz_mul(c, b, b);
		mpz_mod(c, c, p);
		mpz_mul(t, t, c);
		mpz_mod(t, t, p);
		mpz_set(e, i);
	}
	auto finish = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(finish - begin).count();

	printf("Solution:  x = ");
	mpz_out_str(stdout, 10, x);
	printf(" mod ");
	mpz_out_str(stdout, 10, p);
	printf("\n");
	mpz_sub(i, p, x); // i = p - x
	printf("           x = ");
	mpz_out_str(stdout, 10, i);

	mpz_set(out_x, i);

	printf(" mod ");
	mpz_out_str(stdout, 10, p);
	printf("\n");

	std::cout << "\nRunning Time: " << duration << " us" << std::endl;

	mpz_clear(b);
	mpz_clear(temp);
	mpz_clear(i);
	mpz_clear(z);
	mpz_clear(e);
	mpz_clear(c);
	mpz_clear(x);
	mpz_clear(t);
	mpz_clear(p);
	mpz_clear(a);
	mpz_clear(m);
	mpz_clear(s);

	return 1;
}
