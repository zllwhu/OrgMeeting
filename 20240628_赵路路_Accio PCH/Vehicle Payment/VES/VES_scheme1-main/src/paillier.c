#include "../inc/paillier.h"

void paillier_enc(bn_t c, bn_t pub, bn_t m, bn_t r)
{
	// N = pub
	bn_t g, t, tmp, rho;
	bn_null(g);  bn_null(t); bn_null(tmp); bn_null(rho);
	bn_new(g); bn_new(t); bn_new(tmp); bn_new(rho);
	bn_add_dig(g, pub, 1);
	// t = n ** 2 
	bn_sqr(t, pub);
	// c = g^m * r^N mod N^2
	bn_mxp(c, g, m, t);
	bn_mxp(tmp, r, pub, t);
	bn_mul(c, c, tmp);
	bn_mod(c, c, t);
	// 释放变量
	bn_free(g); bn_free(t); bn_free(tmp); bn_free(rho);
}

void init_PaillierKeyPair(PaillierKeyPair_t *kp)
{
	bn_null(kp->prv);
	bn_null(kp->pub);
	bn_new(kp->prv);
	bn_new(kp->pub);
}

void free_PaillierKeyPair(PaillierKeyPair_t *kp)
{
	bn_free(kp->prv);
	bn_free(kp->pub);
}

void gen_PaillierKeyPair(PaillierKeyPair_t *kp, int blen)
{
	init_PaillierKeyPair(kp);
	cp_ghpe_gen(kp->pub, kp->prv, blen);
}