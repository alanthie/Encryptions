https://github.com/jadeblaquiere/ecclib/blob/d9373e575d24a7c8032a59d2420b2678119c3a1a/src/field.c
/* modular square root - return nonzero if not quadratic residue */ 

int mpFp_sqrt(mpFp_t rop, mpFp_t op) {
    int s;
    int leg_op;
    mpz_t t, q, opi;
    mpz_init(opi);
    mpz_set_mpFp(opi, op);
    // determine whether i is a quadratic residue (mod p)
    leg_op = mpz_legendre(opi, op->fp->p);
    if (leg_op < 0) {
        mpz_clear(opi);
        return -1;
    } else if (leg_op == 0) {
        mpFp_set_ui_fp(rop, 0, op->fp);
        mpz_clear(opi);
        return 0;
    }
    mpz_init(t);
    mpz_init(q);

    // tonelli shanks algorithm
    mpz_sub_ui(q, op->fp->p, 1);
    s = 0;
    assert(mpz_cmp_ui(q, 0) != 0);
    while (mpz_tstbit(q, 0) == 0) {
        mpz_tdiv_q_ui(q, q, 2);
        s += 1;
    }
    if (s == 1) {
        // p = 3 mod 4 case, sqrt by exponentiation
        mpz_add_ui(t, op->fp->p, 1);
        mpz_tdiv_q_ui(t, t, 4);
        rop->fp = op->fp;
        mpFp_realloc(rop);
        mpz_powm(rop->i, opi, t, op->fp->p);
    } else {
        int m;
        mpz_t z, c, r, b;
        mpz_init(z);
        mpz_init(c);
        mpz_init(r);
        mpz_init(b);
        mpz_set_ui(z, 2);
        while(mpz_legendre(z, op->fp->p) != -1) {
            mpz_add_ui(z, z, 1);
            assert (mpz_cmp(z, op->fp->p) < 0);
        }
        mpz_powm(c, z, q, op->fp->p);
        mpz_add_ui(t, q, 1);
        mpz_tdiv_q_ui(t, t, 2);
        mpz_powm(r, opi, t, op->fp->p);
        mpz_powm(t, opi, q, op->fp->p);
        m = s;
        while (1) {
            int i;

            if (mpz_cmp_ui(t, 1) == 0) {
                break;
            }
            mpz_set(z, t);
            for (i = 0; i < (m-1); i++) {
                if (mpz_cmp_ui(z, 1) == 0) {
                    break;
                }
                mpz_powm_ui(z, z, 2, op->fp->p);
                //mpz_add_ui(i, i, 1); 
            }
            mpz_powm_ui(b, c, 1 << (m - i - 1), op->fp->p);
            mpz_mul(r, r, b);
            mpz_mod(r, r, op->fp->p);
            mpz_powm_ui(c, b, 2, op->fp->p);
            mpz_mul(t, t, c);
            mpz_mod(t, t, op->fp->p);
            //mpz_set(m, i);
            m = i;
        }
        rop->fp = op->fp;
        mpFp_realloc(rop);
        mpz_set(rop->i, r);
        mpz_clear(b);
        mpz_clear(r);
        mpz_clear(c);
        mpz_clear(z);
    }
    mpz_clear(q);
    mpz_clear(t);
    mpz_clear(opi);

    if (__GMP_UNLIKELY(rop->i->_mp_size < op->fp->psize)) {
        int i;

        for (i = rop->i->_mp_size; i < op->fp->psize; i++) {
            rop->i->_mp_d[i] = 0;
        }
    }

    rop->i->_mp_size = op->fp->psize;
    return 0;
}