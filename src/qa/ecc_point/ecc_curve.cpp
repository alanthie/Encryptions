#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include "ecc_curve.hpp"

int ecc_curve::init_curve(  unsigned int nbits,
                            const std::string& ia, const std::string& ib, const std::string& iprime,
							const std::string& iorder, int icofactor, const std::string& igx, const std::string& igy)
{
    if (verbose) std::cout << "init_curve " << "\n";

    mpz_init_set_str(prime,iprime.data(),10);
	mpz_init_set_str(a,ia.data(),10);
	mpz_init_set_str(b,ib.data(),10);
	mpz_init_set_str(order,iorder.data(),10);
	mpz_init_set_str(generator_point.x,igx.data(),10);
	mpz_init_set_str(generator_point.y,igy.data(),10);
    cofactor = icofactor;

    bits_len = nbits; //bitSize(prime);
    if (verbose)
    {
        std::cout << "BITS " << bits_len  << "\n";
    }

	MSG_BYTES_MAX = bits_len/8;
	MSG_BYTES_MAX -= 1;             // space to find a valid message on curve x+0, 1,...255 - 50% of x are on curve
	MSG_BYTES_PAD = 1;
	if (verbose)
	{
        std::cout << "MSG_BYTES_MAX " << MSG_BYTES_MAX  << "\n";
        std::cout << "MSG_BYTES_PAD " << MSG_BYTES_PAD  << "\n";
	}

	if (existPoint1(generator_point.x,generator_point.y))
    {
        if (verbose) std::cout << "generator_point OK"  << "\n";
		return 0;
	}
	else
	{
        std::cerr << "ERROR invalid  generator_point"  << "\n";
        std::cerr << "Gx "  << igx << "\n";
        std::cerr << "Gy "  << igy << "\n";
		return -1;
    }
}

//if (quadratic_residue(y,l,prime)==1)
int quadratic_residue(mpz_t x, mpz_t q, mpz_t n)
{
    //return test_tonelli(const std::string& sprime, const std::string& sa)
//    mpz_t out_x;
//    char* sp = mpz_get_str(NULL, 10, n);
//    char* sn = mpz_get_str(NULL, 10, q);
//    std::string ssp(sp);
//    std::string ssn(sn);
//    int ret = test_tonelli(ssp, ssn, x); //gmp_printf("x=%Zd\n",x);
//
//    void (*freefunc)(void *, size_t);
//    mp_get_memory_functions (NULL, NULL, &freefunc);
//    freefunc(sp, strlen(sp) + 1);
//    freefunc(sp, strlen(sn) + 1);
//
//    return ret;

    int             leg;
    mpz_t           tmp,ofac,nr,t,r,c,bb; // b??
    unsigned int    mod4;
    mp_bitcnt_t     twofac=0,m,i,ix;

    mod4 = mpz_tstbit(n,0);
    if(!mod4) // must be odd
        return 0;

    mod4+=2*mpz_tstbit(n,1);

    leg=mpz_legendre(q,n);
    if(leg!=1)
        return leg;

    mpz_init_set(tmp,n);

    if(mod4==3) // directly, x = q^(n+1)/4 mod n
    {
        mpz_add_ui(tmp,tmp,1UL);
        mpz_tdiv_q_2exp(tmp,tmp,2);
        mpz_powm(x,q,tmp,n);
        mpz_clear(tmp);
    }
    else // Tonelli-Shanks
    {
        mpz_inits(ofac,t,r,c,bb,NULL);

        // split n - 1 into odd number times power of 2 ofac*2^twofac
        mpz_sub_ui(tmp,tmp,1UL);
        twofac=mpz_scan1(tmp,twofac); // largest power of 2 divisor
        if(twofac)
            mpz_tdiv_q_2exp(ofac,tmp,twofac); // shift right

        // look for non-residue
        mpz_init_set_ui(nr,2UL);
        while(mpz_legendre(nr,n)!=-1)
            mpz_add_ui(nr,nr,1UL);

        mpz_powm(c,nr,ofac,n); // c = nr^ofac mod n

        mpz_add_ui(tmp,ofac,1UL);
        mpz_tdiv_q_2exp(tmp,tmp,1);
        mpz_powm(r,q,tmp,n); // r = q^(ofac+1)/2 mod n

        mpz_powm(t,q,ofac,n);
        mpz_mod(t,t,n); // t = q^ofac mod n

        if(mpz_cmp_ui(t,1UL)!=0) // if t = 1 mod n we're done
        {
            m=twofac;
            do
            {
                i=2;
                ix=1;
                while(ix<m)
                {
                    // find lowest 0 < ix < m | t^2^ix = 1 mod n
                    mpz_powm_ui(tmp,t,i,n); // repeatedly square t
                    if(mpz_cmp_ui(tmp,1UL)==0)
                        break;
                    i<<=1; // i = 2, 4, 8, ...
                    ix++; // ix is log2 i
                }
                mpz_powm_ui(bb,c,1<<(m-ix-1),n); // b = c^2^(m-ix-1) mod n
                mpz_mul(r,r,bb);
                mpz_mod(r,r,n); // r = r*b mod n
                mpz_mul(c,bb,bb);
                mpz_mod(c,c,n); // c = b^2 mod n
                mpz_mul(t,t,c);
                mpz_mod(t,t,n); // t = t b^2 mod n
                m=ix;
            }while(mpz_cmp_ui(t,1UL)!=0); // while t mod n != 1
        }
        mpz_set(x,r);
        mpz_clears(tmp,ofac,nr,t,r,c,bb,NULL);
    }

    return 1;
}

int ecc_curve::existPoint1(mpz_t& x, mpz_t&  y)
{
	mpz_t exp,eq_result;
	mpz_init(eq_result);	//Equation Result
	mpz_init(exp); 			//Exponentiation Result
	mpz_pow_ui(exp,x,3);
	mpz_addmul(exp,x,a);
	mpz_add(exp,exp,b);
	mpz_mod(exp,exp,prime);
	mpz_pow_ui(eq_result,y,2);
	mpz_mod(eq_result,eq_result,prime);
	if (mpz_cmp(eq_result,exp)==0)
		return 1;
	else
		return 0;
}

ecc_point ecc_curve::sum(ecc_point p1, ecc_point p2)
{
	ecc_point r;
	mpz_init(r.x);
	mpz_init(r.y);

	if (mpz_cmp(p1.x,p2.x)==0 && mpz_cmp(p1.y,p2.y)==0)
		r=double_p(p1);
	else
		if( mpz_cmp(p1.x,p2.x)==0 && mpz_cmpabs(p2.y,p1.y)==0)
        {
		    r.is_infinity = true;
        }
		else
        {
			mpz_t delta_x,x,y,delta_y,s,s_2;
			mpz_init(delta_x);
			mpz_init(x); mpz_init(y);
			mpz_init(s); mpz_init(s_2);
			mpz_init(delta_y);
			mpz_sub(delta_x,p1.x,p2.x);
			mpz_sub(delta_y,p1.y,p2.y);
			mpz_mod(delta_x,delta_x,prime);
			mpz_invert(delta_x,delta_x,prime);
			mpz_mul(s,delta_x,delta_y);
			mpz_mod(s,s,prime);
			mpz_pow_ui(s_2,s,2);
			mpz_sub(x,s_2,p1.x);
			mpz_sub(x,x,p2.x);
			mpz_mod(x,x,prime);
			mpz_set(r.x,x);
			mpz_sub(delta_x,p2.x,x);
			mpz_neg(y,p2.y);
			mpz_addmul(y,s,delta_x);
			mpz_mod(y,y,prime);
			mpz_set(r.y,y);
		};
	return r;
}

ecc_point ecc_curve::double_p(ecc_point p)
{
    ecc_point r;
    ecc_point* result = &r;

	mpz_init((*result).x);
	mpz_init((*result).y);

	if (mpz_cmp_ui(p.y,0)!=0)
    {
		mpz_t s,d_y,d_x,y;
		mpz_init(d_y);
		mpz_init(s);
		mpz_init(y);
		mpz_init(d_x);
		mpz_pow_ui(s,p.x,2);
		mpz_mul_si(s,s,3);
		mpz_add(s,s,a);
		mpz_mul_si(d_y,p.y,2);
		mpz_mod(d_y,d_y,prime);
		mpz_invert(d_y,d_y,prime);
		mpz_mul(s,s,d_y);
		mpz_mod(s,s,prime);
		mpz_mul_ui(d_x,p.x,2);
		mpz_pow_ui((*result).x,s,2);
		mpz_sub((*result).x,(*result).x,d_x);
		mpz_mod((*result).x,(*result).x,prime);
		mpz_neg((*result).y,p.y);
		mpz_sub(d_x,p.x,(*result).x);
		mpz_mul(s,s,d_x);
		mpz_add((*result).y,(*result).y,s);
		mpz_mod((*result).y,(*result).y,prime);
	}
    else
    {
		r.is_infinity = true;
    }
	return r;
}

ecc_point ecc_curve::mult(ecc_point p, mpz_t value)
{
    ecc_point r;

	if (mpz_cmp_ui(value,0)==0)
		{r.is_valid=false;return r;}

	if (mpz_cmp_ui(value,1)==0)
		return (p);

	if (mpz_cmp_ui(value,2)==0)
		return double_p(p);

	mpz_t aux,aux1;
	mpz_init_set(aux,value);
	mpz_init_set(aux1,value);
	if (mpz_cmp_ui(aux,0)!=0)
    {
		mpz_mod_ui(aux,aux,2);
		if (mpz_cmp_ui(aux,0) != 0 )
        {
			mpz_sub_ui(aux1,aux1,1);
			r = sum(p, mult(p,aux1) );
		}else
		{
			mpz_set(aux,value);
			mpz_div_ui(aux1,aux1,2);
			r = double_p(mult(p,aux1));
		}
	}
	return r;

}

ecc_point ecc_curve::existPoint(mpz_t&  p)
{
    ecc_point r;

	mpz_t l;
	mpz_init(l);
	mpz_pow_ui(l,p,3);
	mpz_addmul(l,a,p);
	mpz_add(l,l,b);
	mpz_mod(l,l,prime);
	mpz_t i;
	mpz_init_set_ui(i,0);
	mpz_t y;
	mpz_init(y);
	if (quadratic_residue(y,l,prime)==1)
    {
		mpz_init_set(r.x,p);
		mpz_init_set(r.y,y);
		return r;
	}
    else
    {
        r.is_valid = false;
		return r;
    }
}

bool ecc_curve::encode(ecc_point& out_Cm, ecc_point& out_rG, const std::string& msg, ecc_point& publicKey, mpz_t& private_key)
{
    cryptoAL::Buffer buffer_message;
    message_point Pm;

    bool r = format_msg_for_ecc(msg, buffer_message);
	if (r==false)
	{
        std::cerr << "ERROR formatting input msg for encoding" << std::endl;
        return false;
	}

	Pm = getECCPointFromMessage(buffer_message);
	if (Pm.p.is_valid == false)
    {
        std::cerr << "ERROR message encoding on elliptic curve" << std::endl;
		return false;
	}

	out_rG = mult(generator_point, private_key);
	ecc_point rPub  = mult(publicKey, private_key);
	out_Cm = sum(Pm.p, rPub);
	return true;
}

bool ecc_curve::decode(ecc_point& in_Cm, ecc_point& in_rG, std::string& out_msg, mpz_t& private_key)
{
	ecc_point rGPriv = mult(in_rG, private_key);

    message_point Pm;
    mpz_neg(rGPriv.y,rGPriv.y); //-rGPriv.y
	Pm.p = sum(in_Cm, rGPriv);  // Cm-rGPriv

	cryptoAL::Buffer out_message;
	getMessageFromPoint(Pm, out_message);
	if (Pm.p.is_valid == false)
	{
        std::cerr << "ERROR decoding message from elliptic curve" << std::endl;
        return false;
	}

	out_msg = std::string(out_message.getdata(), out_message.size()); // not zero ended buffer out_message
	if (verbose)
        std::cout <<"message from [Cm-rGPriv] point: " << out_msg << " size: " << out_msg.size() << std::endl;

	return true;
}

/* Solve the modular equatioon x^2 = n (mod p) using the Shanks-Tonelli
 * algorihm. x will be placed in q and 1 returned if the algorithm is
 * successful. Otherwise 0 is returned (currently in case n is not a quadratic
 * residue mod p). A check is done if p = 3 (mod 4), in which case the root is
 * calculated as n ^ ((p 1) / 4) (mod p).
 *
 * Note that currently mpz_legendre is called to make sure that n really is a
 * quadratic residue. The check can be skipped, at the price of going into an
 * eternal loop if called with a non-residue.
 */
//https://github.com/mounirnasrallah/Quadratic-Sieve/blob/master/src/mpz_sqrtm.c
int mpz_sqrtm(mpz_t q, const mpz_t n, const mpz_t p) {
    mpz_t w, n_inv, y;
    unsigned int i, s;

      if(mpz_divisible_p(n, p)) {         /* Is n a multiple of p?            */
          mpz_set_ui(q, 0);               /* Yes, then the square root is 0.  */
          return 1;                       /* (special case, not caught        */
      }                                   /* otherwise)                       */

      if(mpz_tstbit(p, 1) == 1) {         /* p = 3 (mod 4) ?                  */
          mpz_set(q, p);
          mpz_add_ui(q, q, 1);
          mpz_fdiv_q_2exp(q, q, 2);
          mpz_powm(q, n, q, p);           /* q = n ^ ((p 1) / 4) (mod p)      */
          return 1;
      }

      mpz_init(y);
      mpz_init(w);
      mpz_init(n_inv);

      mpz_set(q, p);
      mpz_sub_ui(q, q, 1);                /* q = p-1                          */
      s = 0;                              /* Factor out 2^s from q            */
      while(mpz_tstbit(q, s) == 0) s++  ;
      mpz_fdiv_q_2exp(q, q, s);           /* q = q / 2^s                      */
      mpz_set_ui(w, 2);                   /* Search for a non-residue mod p   */
      while(mpz_legendre(w, p) != -1)     /* by picking the first w such that */
          mpz_add_ui(w, w, 1);            /* (w/p) is -1                      */
      mpz_powm(w, w, q, p);               /* w = w^q (mod p)                  */
      mpz_add_ui(q, q, 1);
      mpz_fdiv_q_2exp(q, q, 1);           /* q = (q 1) / 2                    */
      mpz_powm(q, n, q, p);               /* q = n^q (mod p)                  */
      mpz_invert(n_inv, n, p);
      for(;;) {
          mpz_powm_ui(y, q, 2, p);        /* y = q^2 (mod p)                  */
          mpz_mul(y, y, n_inv);
          mpz_mod(y, y, p);               /* y = y * n^-1 (mod p)             */
          i = 0;
          while(mpz_cmp_ui(y, 1) != 0) {
          //https://gmplib.org/list-archives/gmp-devel/2006-May/000633.html
              i++;
              mpz_powm_ui(y, y, 2, p);    /*  y = y ^ 2 (mod p)               */
          }
          if(i == 0) {                    /* q^2 * n^-1 = 1 (mod p), return   */
              return 1;
          }
          if(s-i == 1) {                  /* In case the exponent to w is 1,  */
              mpz_mul(q, q, w);           /* Don't bother exponentiating      */
          } else {
              mpz_powm_ui(y, w, 1 << (s-i-1), p);
              mpz_mul(q, q, y);
          }
          mpz_mod(q, q, p);               /* r = r * w^(2^(s-i-1)) (mod p)    */
      }

      mpz_clear(w); mpz_clear(n_inv); mpz_clear(y);
      return 0;
}
