/**
  * JAIST - Visiting Student 2014
  * Iskandar Setiadi s1416051@jaist.ac.jp
  *
  */

#include "boolean.hpp"
#include "helper.hpp"
#include "point.hpp"
#include "j_point.hpp"
#include "ecc.hpp"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <gmpxx.h>
//#include <gmp.h>


namespace cryptoSimpleECC
{

// Define your TEST here
#define TEST_MODULAR_OPERATION false
#define TEST_SCALAR_OPERATION false
#define TEST_SCALAR_ALGORITHM false
#define TEST_ENCRYPT_DECRYPT true
#define TEST_SIMPLIFIED_ECIES false


long long max_iteration;

// ECC Parameters (P-256 NIST)
char*a_v="-3";
char*b_v="5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
char*p_v="115792089210356248762697446949407573530086143415290314195533631308867097853951";
char*r_v="115792089210356248762697446949407573529996955224135760342422259061068512044369";
char*gx_v="6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
char*gy_v="4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
char*s_v="c49d360886e704936a6678e1139d26b7819f7e90";
char*c_v="7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d";

/** This benchmarking code is adapted from https://idea.popcount.org/2013-01-28-counting-cycles---rdtsc/ */
#ifdef __i386__
#  define RDTSC_DIRTY "%eax", "%ebx", "%ecx", "%edx"
#elif __x86_64__
#  define RDTSC_DIRTY "%rax", "%rbx", "%rcx", "%rdx"
#else
# error unknown platform
#endif

#define RDTSC_START(cycles)                                \
    do {                                                   \
        register unsigned cyc_high, cyc_low;               \
        asm volatile("CPUID\n\t"                           \
                     "RDTSC\n\t"                           \
                     "mov %%edx, %0\n\t"                   \
                     "mov %%eax, %1\n\t"                   \
                     : "=r" (cyc_high), "=r" (cyc_low)     \
                     :: RDTSC_DIRTY);                      \
        (cycles) = ((uint64_t)cyc_high << 32) | cyc_low;   \
    } while (0)

#define RDTSC_STOP(cycles)                                 \
    do {                                                   \
        register unsigned cyc_high, cyc_low;               \
        asm volatile("RDTSCP\n\t"                          \
                     "mov %%edx, %0\n\t"                   \
                     "mov %%eax, %1\n\t"                   \
                     "CPUID\n\t"                           \
                     : "=r" (cyc_high), "=r" (cyc_low)     \
                     :: RDTSC_DIRTY);                      \
        (cycles) = ((uint64_t)cyc_high << 32) | cyc_low;   \
    } while(0)

uint64_t t1, t2;
// Constants, the minimum number of cycles required for calling RDTSC_START and RDTSC_STOP
uint64_t rdtscp_cycle = 50;

void print_result(uint64_t cycle, uint64_t one_us) {
	printf("Number of iteration: %lld\n", max_iteration);
	printf("Average number of cycles: %.2f cycles\n", ((double) cycle / max_iteration));
	printf("Average elapsed time: %.8f us\n\n", ((double) cycle / one_us) / max_iteration);
}



int test_simple_ecc() {
	/** Fm, where modulo = m */
	mpz_t a, b, k, r, modulo;
	int i = 0; // loop variable
	Point p, next_p;
	p = init_point(p);
	mpz_init(a);
	mpz_init(b);
	mpz_init(k);
	mpz_init(r); // order
	mpz_init(modulo);

	/** Initialize parameters of ECC (F2p) */
	mpz_set_str(a, a_v, 10);
	mpz_set_str(b, b_v, 16);
	mpz_set_str(modulo, p_v, 10);
	mpz_set_str(r, r_v, 10);
	mpz_set_str(p.x, gx_v, 16);
	mpz_set_str(p.y, gy_v, 16);

	mpz_t zero_value, k2;
	mpz_init(zero_value);
	mpz_init(k2);

	RDTSC_START(t1);

	sleep(1); // sleep for 1 second

	RDTSC_STOP(t2);
	uint64_t one_second = t2 - t1 - rdtscp_cycle;
	printf("Approximate number of cycles in 1 second: %lld\n\n", one_second);
	uint64_t one_us = one_second / 1e6;

	while (mpz_cmp(k, zero_value) == 0) {
		get_random(k, 32); // generate random test (256 bits)
		positive_modulo(k, k, modulo);
	}
	printf("Random k (in Binary): ");
	mpz_out_str(stdout, 2, k);
	printf("\n");

	while (mpz_cmp(k2, zero_value) == 0) {
		get_random(k2, 32); // generate random test (256 bits)
		positive_modulo(k2, k2, modulo);
	}
	printf("Random k2 (in Binary): ");
	mpz_out_str(stdout, 2, k2);
	printf("\n");

	/** Compare ADDITION, SHIFTING, MULTIPLICATION, and INVERSION */
	if (TEST_MODULAR_OPERATION) {
		max_iteration = 10000;

		/** Addition */
		i = 0;
		uint64_t total = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			mpz_add(k, k, k2);
			positive_modulo(k, k, modulo);
			RDTSC_STOP(t2); // stop operation
			total += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[ADDITION]--\n");
		print_result(total, one_us);


		/** Shifting */
		i = 0;
		uint64_t total2 = 0;
		mpz_t two;
		mpz_init(two);
		mpz_set_si(two, 2);
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			mpz_mul_2exp(k, k, 1); // left shift
			positive_modulo(k, k, modulo);
			RDTSC_STOP(t2); // stop operation
			total2 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[SHIFTING 2 * k]--\n");
		print_result(total2, one_us);

		/** Multiplication */
		i = 0;
		uint64_t total3 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			mpz_mul(k, k, k2);
			positive_modulo(k, k, modulo);
			RDTSC_STOP(t2); // stop operation
			total3 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[MULTIPLICATION k * k2]--\n");
		print_result(total3, one_us);

		/** Inversion */
		i = 0;
		uint64_t total4 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			mpz_invert(k, k, modulo);
			RDTSC_STOP(t2); // stop operation
			total4 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[INVERSION]--\n");
		print_result(total4, one_us);
	}

	/** -------------------------------------------------------------------------*/
	// Convert Affine coordinate to Jacobian coordinate
	J_Point j_p, j_next_p;
	j_next_p = init_j_point(j_next_p);
	j_p = affine_to_jacobian(p); // Generator point

	if (TEST_SCALAR_OPERATION) {
		max_iteration = 100;
		Point p1, p2, p3;
		J_Point j_p1, j_p2, j_p3;

		/** Point preparation */
		p1 = init_point(p1); p2 = init_point(p2);
		j_p1 = init_j_point(j_p1); j_p2 = init_j_point(j_p2);
		j_p1 = jacobian_affine_sliding_NAF(j_p, p, a, k, modulo, 4);
		j_p2 = jacobian_affine_sliding_NAF(j_p, p, a, k2, modulo, 4);
		p1 = jacobian_to_affine(j_p1, modulo);
		p2 = jacobian_to_affine(j_p2, modulo);

		/** Affine addition */
		i = 0;
		uint64_t total = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			p3 = affine_curve_addition(p1, p2, a, modulo);
			RDTSC_STOP(t2); // stop operation
			total += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[ADDITION in AFFINE]--\n");
		print_result(total, one_us);

		/** Affine doubling */
		i = 0;
		uint64_t total2 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			p3 = affine_curve_doubling(p1, a, modulo);
			RDTSC_STOP(t2); // stop operation
			total2 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[DOUBLING in AFFINE]--\n");
		print_result(total2, one_us);

		/** Jacobian addition */
		i = 0;
		uint64_t total3 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_p3 = jacobian_curve_addition(j_p1, j_p2, a, modulo);
			RDTSC_STOP(t2); // stop operation
			total3 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[ADDITION in JACOBIAN]--\n");
		print_result(total3, one_us);

		/** Jacobian doubling */
		i = 0;
		uint64_t total4 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_p3 = jacobian_curve_doubling(j_p1, a, modulo);
			RDTSC_STOP(t2); // stop operation
			total4 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[DOUBLING in JACOBIAN]--\n");
		print_result(total4, one_us);

		/** Affine-Jacobian addition */
		i = 0;
		uint64_t total5 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_p3 = jacobian_affine_curve_addition(j_p1, p2, a, modulo);
			RDTSC_STOP(t2); // stop operation
			total5 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[ADDITION in JACOBIAN-AFFINE]--\n");
		print_result(total5, one_us);
	}

	/** -------------------------------------------------------------------------*/
	if (TEST_SCALAR_ALGORITHM) {
		max_iteration = 100;

		/** Test Left-to-right binary algorithm */
		i = 0;
		uint64_t total = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			next_p = affine_left_to_right_binary(p, a, k, modulo); // Q = [k]P
			// gmp_printf("%Zd %Zd\n", next_p.x, next_p.y);
			RDTSC_STOP(t2); // stop operation
			total += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[AFFINE] Left to right binary algorithm--\n");
		print_result(total, one_us);

		i = 0;
		uint64_t total2 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_next_p = jacobian_left_to_right_binary(j_p, a, k, modulo); // Q = [k]P
			// gmp_printf("%Zd %Zd\n", j_next_p.X, j_next_p.Y);
			next_p = jacobian_to_affine(j_next_p, modulo);
			// gmp_printf("%Zd %Zd\n", next_p.x, next_p.y);
			RDTSC_STOP(t2); // stop operation
			total2 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[JACOBIAN] Left to right binary algorithm--\n");
		print_result(total2, one_us);

		i = 0;
		uint64_t total3 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_next_p = jacobian_affine_left_to_right_binary(j_p, p, a, k, modulo); // Q = [k]P
			// gmp_printf("%Zd %Zd\n", j_next_p.X, j_next_p.Y);
			next_p = jacobian_to_affine(j_next_p, modulo);
			// gmp_printf("%Zd %Zd\n", next_p.x, next_p.y);
			RDTSC_STOP(t2); // stop operation
			total3 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[JACOBIAN-AFFINE] Left to right binary algorithm--\n");
		print_result(total3, one_us);

		int w = 4; // windows size
		i = 0;
		uint64_t total4 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_next_p = jacobian_affine_sliding_NAF(j_p, p, a, k, modulo, w); // Q = [k]P
			// gmp_printf("%Zd %Zd\n", j_next_p.X, j_next_p.Y);
			next_p = jacobian_to_affine(j_next_p, modulo);
			// gmp_printf("%Zd %Zd\n", next_p.x, next_p.y);
			RDTSC_STOP(t2); // stop operation
			total4 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[JACOBIAN-AFFINE] Sliding NAF Left to right binary algorithm (w = 4)--\n");
		print_result(total4, one_us);

		w = 5; // windows size
		i = 0;
		uint64_t total5 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_next_p = jacobian_affine_sliding_NAF(j_p, p, a, k, modulo, w); // Q = [k]P
			// gmp_printf("%Zd %Zd\n", j_next_p.X, j_next_p.Y);
			next_p = jacobian_to_affine(j_next_p, modulo);
			// gmp_printf("%Zd %Zd\n", next_p.x, next_p.y);
			RDTSC_STOP(t2); // stop operation
			total5 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[JACOBIAN-AFFINE] Sliding NAF Left to right binary algorithm (w = 5)--\n");
		print_result(total5, one_us);

		/** Test Right-to-left binary algorithm */
		i = 0;
		uint64_t total6 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			next_p = affine_right_to_left_binary(p, a, k, modulo); // Q = [k]P
			// gmp_printf("%Zd %Zd\n", next_p.x, next_p.y);
			RDTSC_STOP(t2); // stop operation
			total6 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[AFFINE] Right to left binary algorithm--\n");
		print_result(total6, one_us);

		/** Test Montgomery ladder algorithm (Against time-based attack) */
		i = 0;
		uint64_t total7 = 0;
		while (i < max_iteration) {
			RDTSC_START(t1); // start operation
			j_next_p = jacobian_montgomery_ladder(j_p, a, k, modulo); // Q = [k]P
			// gmp_printf("%Zd %Zd\n", j_next_p.X, j_next_p.Y);
			next_p = jacobian_to_affine(j_next_p, modulo);
			// gmp_printf("%Zd %Zd\n", next_p.x, next_p.y);
			RDTSC_STOP(t2); // stop operation
			total7 += t2 - t1 - rdtscp_cycle;
			i++;
		}
		printf("--[JACOBIAN] Montgomery ladder algorithm--\n");
		print_result(total7, one_us);
	}

	/** -------------------------------------------------------------------------*/
	J_Point public_key_1, public_key_2, shared_key;
	mpz_t private_key_1, private_key_2;
	mpz_init(private_key_1); mpz_init(private_key_2);
	// TODO : Key should be padded to fixed size (serializable)
	// Note: (2^-256 chance of failure, can be ignored)
	while (mpz_cmp(private_key_1, zero_value) == 0) {
		get_random(private_key_1, 32); // 256 bit
		positive_modulo(private_key_1, private_key_1, modulo);
	}
	while (mpz_cmp(private_key_2, zero_value) == 0) {
		get_random(private_key_2, 32); // 256 bit
		positive_modulo(private_key_2, private_key_2, modulo);
	}

	gmp_printf("Private key [A B]: %Zd %Zd\n\n", private_key_1, private_key_2);
	public_key_1 = jacobian_left_to_right_binary(j_p, a, private_key_1, modulo);
	public_key_2 = jacobian_left_to_right_binary(j_p, a, private_key_2, modulo);

	gmp_printf("Public key 1 - Jacobian [X Y Z]: %Zd %Zd %Zd\n", public_key_1.X, public_key_1.Y, public_key_1.Z);
	gmp_printf("Public key 2 - Jacobian [X Y Z]: %Zd %Zd %Zd\n", public_key_2.X, public_key_2.Y, public_key_2.Z);

	Point public_key_1_decoded = jacobian_to_affine(public_key_1, modulo);
	Point public_key_2_decoded = jacobian_to_affine(public_key_2, modulo);

	gmp_printf("Public key 1 - Affine [X Y]: %Zd %Zd\n", public_key_1_decoded.x, public_key_1_decoded.y);
	gmp_printf("Public key 2 - Affine [X Y]: %Zd %Zd\n\n", public_key_2_decoded.x, public_key_2_decoded.y);

	/** -------------------------------------------------------------------------*/
	if (TEST_ENCRYPT_DECRYPT) {
		// ElGamal Encrypt - Decrypt (Map message to chunk of points in EC)
		J_Point message, chosen_point, encoded_point, decoded_point;
		mpz_t k_message;
		mpz_init(k_message);
		mpz_set_ui(k_message, 123456789);
		message = jacobian_left_to_right_binary(j_p, a, k_message, modulo);

		Point message_decoded = jacobian_to_affine(message, modulo);
		gmp_printf("[Encrypt] Message - Affine [X Y] %Zd %Zd\n", message_decoded.x, message_decoded.y);
		gmp_printf("[Encrypt] Message - Jacobian [X Y Z]: %Zd %Zd %Zd\n", message.X, message.Y, message.Z);
		while (mpz_cmp(k_message, zero_value) == 0) {
			get_random(k_message, 32);
			positive_modulo(k_message, k_message, modulo);
		}
		// Encrypt example
		chosen_point = jacobian_left_to_right_binary(j_p, a, k_message, modulo); // chosen point (r)
		gmp_printf("[Encrypt] Chosen point - Jacobian [X Y Z]: %Zd %Zd %Zd\n", chosen_point.X, chosen_point.Y, chosen_point.Z);
		encoded_point = jacobian_left_to_right_binary(public_key_2, a, k_message, modulo); // r * Pu2
		encoded_point = jacobian_curve_addition(message, encoded_point, a, modulo);
		// TODO : chosen_point & encoded_point should be padded to P-bit
		gmp_printf("[Decrypt] Encoded point - Jacobian [X Y Z]: %Zd %Zd %Zd\n", encoded_point.X, encoded_point.Y, encoded_point.Z);

		// Decrypt example (encoded_point - private_key * chosen_point)
		decoded_point = jacobian_left_to_right_binary(chosen_point, a, private_key_2, modulo);
		decoded_point = jacobian_curve_subtraction(encoded_point, decoded_point, a, modulo);
		gmp_printf("[Decrypt] Original message - Jacobian [X Y Z]: %Zd %Zd %Zd\n", decoded_point.X, decoded_point.Y, decoded_point.Z);
		message_decoded = jacobian_to_affine(decoded_point, modulo);
		gmp_printf("[Decrypt] Original message - Affine [X Y] %Zd %Zd\n\n", message_decoded.x, message_decoded.y);
	}
	/** -------------------------------------------------------------------------*/
	if (TEST_SIMPLIFIED_ECIES) {
		// Simplified ECIES (Ref: Page 256 Cryptography Theory & Practice 2nd Ed. - Douglas)
		char* message_string = "hello"; // 0..9, a..z (base 36)
		mpz_t encrypted_message;
		mpz_init(encrypted_message);

		int partition = strlen(message_string) / 24;
		int partition_modulo = strlen(message_string) % 24;
		if (partition_modulo != 0) partition++;

		for (i = 0; i < partition; i++) {
			// 24 characters from message_string + 1 null-terminate
			char* chunked_message_string = (char*) malloc(25 * sizeof(char));
			int size = 24;
			if ((i == partition - 1) && (partition_modulo != 0)) size = partition_modulo;
			strncpy(chunked_message_string, message_string + i*24, size);
			chunked_message_string[size] = '\0'; // null-terminate

			Point c_point = encrypt_ECIES(encrypted_message, chunked_message_string, public_key_2_decoded, p, a, modulo);
			gmp_printf("[SIMPLIFIED ECIES] Encrypted message: %Zd\n", encrypted_message);
			decrypt_ECIES(encrypted_message, c_point, private_key_2, p, a, modulo);
		}
	}
	/**-------------------------------------------------------------------------*/
	// TODO : Public key validation!
	// Shared key (ECDH) - key secure exchange
	shared_key = jacobian_left_to_right_binary(public_key_2, a, private_key_1, modulo);
	gmp_printf("Shared key - Jacobian [X Y Z]: %Zd %Zd %Zd\n", shared_key.X, shared_key.Y, shared_key.Z);
	Point shared_key_decoded = jacobian_to_affine(shared_key, modulo);
	gmp_printf("Shared key - Affine [X Y]: %Zd %Zd\n", shared_key_decoded.x, shared_key_decoded.y);

	// TODO : ECDSA - digital signature algorithm

	/** Cleaning up */
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(k);
	mpz_clear(r);
	mpz_clear(modulo);
	mpz_clear(private_key_1);
	mpz_clear(private_key_2);

	return EXIT_SUCCESS;
}
/* Created by freedomofkeima - 2014 */
}
