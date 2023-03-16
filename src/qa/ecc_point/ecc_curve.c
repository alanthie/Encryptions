#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "ecc_curve.h"

#define BASE_16 16

int init_curve(char* a1, char* b1,char* prime1, char* order1,int cofactor1,ecc_point g1){
	mpz_init_set_str(a,a1,BASE_16);
	mpz_init_set_str(b,b1,BASE_16);
	mpz_init_set_str(prime,prime1,BASE_16);
	mpz_init_set_str(order,order1,BASE_16);

	cofactor= cofactor1;
	if ( existPoint1(g1.x,g1.y)){
		generator_point=g1;
		return 0;
	}else
		return -1;
}


int quadratic_residue(mpz_t x,mpz_t q,mpz_t n)
{
    int                        leg;
    mpz_t                        tmp,ofac,nr,t,r,c,b;
    unsigned int            mod4;
    mp_bitcnt_t                twofac=0,m,i,ix;

    mod4=mpz_tstbit(n,0);
    if(!mod4) // must be odd
        return 0;

    mod4+=2*mpz_tstbit(n,1);

    leg=mpz_legendre(q,n);
    if(leg!=1)
        return leg;

    mpz_init_set(tmp,n);
	
    if(mod4==3) // directly, x = q^(n+1)/4 mod n
        {
	printf("diretamente\n\n");
        mpz_add_ui(tmp,tmp,1UL);
        mpz_tdiv_q_2exp(tmp,tmp,2);
        mpz_powm(x,q,tmp,n);
	gmp_printf("NUMERO X %Zd \n\n",x);
        mpz_clear(tmp);
        }
    else // Tonelli-Shanks
        {
	printf("Tonelli shanks!!!\n");
        mpz_inits(ofac,t,r,c,b,NULL);

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
                mpz_powm_ui(b,c,1<<(m-ix-1),n); // b = c^2^(m-ix-1) mod n
                mpz_mul(r,r,b);
                mpz_mod(r,r,n); // r = r*b mod n
                mpz_mul(c,b,b);
                mpz_mod(c,c,n); // c = b^2 mod n
                mpz_mul(t,t,c);
                mpz_mod(t,t,n); // t = t b^2 mod n
                m=ix;
                }while(mpz_cmp_ui(t,1UL)!=0); // while t mod n != 1
            }
        mpz_set(x,r);
        mpz_clears(tmp,ofac,nr,t,r,c,b,NULL);
        }

    return 1;
}



int existPoint1(mpz_t x, mpz_t  y){
	mpz_t exp,eq_result;
	mpz_init(eq_result);	//Equation Result
	mpz_init(exp); 			//Exponentiation Result
	mpz_pow_ui(exp,x,3);
	mpz_addmul(exp,x,a);
	mpz_add(exp,exp,b);	
	gmp_printf("%Zd x \n",exp);
	mpz_mod(exp,exp,prime);
	mpz_pow_ui(eq_result,y,2);
	mpz_mod(eq_result,eq_result,prime);
	if (mpz_cmp(eq_result,exp)==0)
		return 1;
	else
		return 0;
}

ecc_point* sum(ecc_point p1,ecc_point p2){
	ecc_point* result;
	result = malloc(sizeof(ecc_point));
	mpz_init((*result).x);
	mpz_init((*result).y);
	if (mpz_cmp(p1.x,p2.x)==0 && mpz_cmp(p1.y,p2.y)==0)
		result=double_p(p1);
	else
		if( mpz_cmp(p1.x,p2.x)==0 && mpz_cmpabs(p2.y,p1.y)==0)
			result=INFINITY_POINT;
		else{
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
			mpz_set((*result).x,x);
			mpz_sub(delta_x,p2.x,x);
			mpz_neg(y,p2.y);
			mpz_addmul(y,s,delta_x);
			mpz_mod(y,y,prime);
			mpz_set((*result).y,y);
		};
	return result;	
}

ecc_point* double_p(ecc_point p){
	ecc_point* result;
	result= malloc(sizeof(ecc_point));
	mpz_init((*result).x);
	mpz_init((*result).y);
	printf("DP ");
	if (mpz_cmp_ui(p.y,0)!=0){
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
	}else
		result=INFINITY_POINT;
	return result;
}

ecc_point* mult(ecc_point p, mpz_t value){
	ecc_point* result ;
	result =malloc(sizeof(ecc_point));
	if (mpz_cmp_ui(value,0)==0)
		return NULL;
	if (mpz_cmp_ui(value,1)==0)
		return (&p);
	if (mpz_cmp_ui(value,2)==0)
		return double_p(p);
	mpz_t aux,aux1;
	mpz_init_set(aux,value);
	mpz_init_set(aux1,value);
	if (mpz_cmp_ui(aux,0)!=0){
		mpz_mod_ui(aux,aux,2);
		if (mpz_cmp_ui(aux,0) != 0 ){
			mpz_sub_ui(aux1,aux1,1);
			result = sum(p, (*mult(p,aux1)));
		}else{
			mpz_set(aux,value);
			mpz_div_ui(aux1,aux1,2);
			result = double_p((*mult(p,aux1)));
		}
	}
	return result;

} 

ecc_point* existPoint(mpz_t  p){
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
	if (quadratic_residue(y,l,prime)==1){
		gmp_printf("entrei");

		ecc_point* r= malloc(sizeof(ecc_point));
		mpz_init_set((*r).x,p);
		mpz_init_set((*r).y,y);
		return r;
	} else
		return NULL;
/*	while(mpz_cmp(i,prime)!=0){
		mpz_set(y,i);
		mpz_pow_ui(y,y,2);
		mpz_mod(y,y,prime);
		gmp_printf(" x %Zd Y %Zd \n",l,y);
		if (mpz_cmp(y,l)==0){
			ecc_point* r= malloc(sizeof(ecc_point));
			mpz_init_set((*r).x,p);
			mpz_init_set((*r).y,i);
			return r;
		}else
			mpz_add_ui(i,i,1);
	}*/
	return NULL;
}

