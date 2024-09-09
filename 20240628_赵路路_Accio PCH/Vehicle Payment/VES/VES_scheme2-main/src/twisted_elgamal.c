#include "../inc/twisted_elgamal.h"

ep_t G1;
ep_t G2;

void init_twisted_elgamal_PP()
{
	ep_null(G1); ep_null(G2);
	ep_new(G1); ep_new(G2);
	uint8_t g[33];
	ep_write_bin(g, 33, G, 1);
	ep_map(G1, g, 33);
	// In order to use bulletproof, so G2 has to be the generator of EC
	// ep_write_bin(g, 33, G1, 1);
	// ep_map(G2, g, 33);
	ep_copy(G2, G);
}

void free_twisted_elgamal_PP()
{
	ep_free(G1);
	ep_free(G2);
}

void init_TwistedKeyPair(Twisted_KeyPair_t *kp)
{
	bn_null(kp->t);
	bn_new(kp->t);
	ep_null(kp->T);
	ep_new(kp->T);
}

void free_TwistedKeyPair(Twisted_KeyPair_t *kp)
{
	bn_free(kp->t);
	ep_free(kp->T);
}

void genTwistedKeyPair(Twisted_KeyPair_t *kp)
{
	init_TwistedKeyPair(kp);
	// 随机选取私钥d属于[1, n-1]
	bn_rand_mod(kp->t, N_1);
	bn_add_dig(kp->t, kp->t, 1);
	ep_mul(kp->T, G2, kp->t);
}

int gen_pre_compute_table(PRE_COMPUTE_TABLE table[1 << 16], ep_t g)
{
	// 一定要全部置零
	memset(table, 0, (1 << 16) * sizeof(PRE_COMPUTE_TABLE));
	uint32_t i, j;
	ep_t p;
	ep_new(p);
	ep_set_infty(p);
	for (i = 0; i < (1 << 16); i++)
	{
		ep_add_basic(p, p, g);
		fp_write_bin(table[i].x_coordinate, 32, p->x);
		j = ((uint16_t)table[i].x_coordinate[30] << 8) | table[i].x_coordinate[31];
		assert(table[j].offset_count <= PRE_COMPUTE_MAX_OFFSETS);
		table[j].offset[table[j].offset_count] = (uint16_t)i;
		(table[j].offset_count)++;
	}
	ep_null(p);
	return 1;
}

static int pre_compute_get_offset(const PRE_COMPUTE_TABLE table[1 << 16], const uint8_t x[32], uint16_t *offset)
{
	uint32_t i = ((uint16_t)x[30] << 8) | x[31];
	uint16_t j;
	uint8_t w;
	for (w = 0; w < table[i].offset_count; w++)
	{
		j = table[i].offset[w];
		if (memcmp(x, table[j].x_coordinate, 32) == 0)
		{
			*offset = j;
			return 1;
		}
	}
	return 0;
}

int solve_ecdlp(const PRE_COMPUTE_TABLE table[1 << 16], ep_t SP, ep_t P, uint32_t *x)
{
	ep_t GP, XG;
	ep_new(GP); ep_new(XG);
	ep_copy(XG, SP);
	bn_t bs;
	bn_new(bs);
	bn_set_dig(bs, 65536);
	ep_mul(GP, P, bs);
	ep_neg(GP, GP);
	int ret = 0;
	uint8_t x_bytes[32];
	uint32_t i;
	uint16_t j;
	for (i = 0; i < (1 << 16); i++)
	{
		if (ep_is_infty(XG))
		{
			*x = (i << 16);
			ret = 1;
			break;
		}
		fp_write_bin(x_bytes, 32, XG->x);
		if (pre_compute_get_offset(table, x_bytes, &j) == 1)
		{
			*x = (i << 16) + j + 1;
			ret = 1;
			break;
		}
		ep_add_basic(XG, XG, GP);
	}
	ep_free(GP); ep_free(XG); bn_free(bs);
	return 1;
}

void twisted_elgamal_enc(ep_t U, ep_t V, ep_t T, uint32_t msg)
{
	bn_t m, beta;
	bn_null(m); bn_null(beta);
	bn_new(m); bn_new(beta);
	bn_set_dig(m, msg);
	ep_t tmp;
	ep_new(tmp);
	// choose a random number beta in [1, n-1]
	bn_rand_mod(beta, N_1);
	bn_add_dig(beta, beta, 1);
	// C = (U, V) = ([m]G1 + [beta]G2, [beta]T)
	ep_mul(tmp, G1, m);
	ep_mul(U, G2, beta);
	ep_add_basic(U, U, tmp);
	ep_mul(V, T, beta);
	bn_free(m); bn_free(beta);
	ep_free(tmp);
}

void twisted_elgamal_encV2(ep_t U, ep_t V, ep_t T, uint32_t msg, bn_t beta)
{
	bn_t m;
	bn_null(m);
	bn_new(m);
	bn_set_dig(m, msg);
	ep_t tmp;
	ep_new(tmp);
	// C = (U, V) = ([m]G1 + [beta]G2, [beta]T)
	ep_mul(tmp, G1, m);
	ep_mul(U, G2, beta);
	ep_add_basic(U, U, tmp);
	ep_mul(V, T, beta);
	bn_free(m);
	ep_free(tmp);
}

void twisted_elgamal_dec(const PRE_COMPUTE_TABLE table[1 << 16], ep_t U, ep_t V, bn_t t, uint32_t *m)
{
	ep_t tmp;
	ep_new(tmp);
	bn_t t_inv;
	bn_new(t_inv);
	// t_inv = t ^ -1 mod n
	bn_mod_inv(t_inv, t, N);
	// M = U - [t_inv]V = [m]G1 + [beta]G2 - [beta]G2 = [m]G1
	ep_mul(tmp, V, t_inv);
	ep_neg(tmp, tmp);
	ep_add_basic(tmp, U, tmp);
	// solve [m]G1 to get m
	solve_ecdlp(table, tmp, G1, m);
	ep_free(tmp);
	bn_free(t_inv);
}
