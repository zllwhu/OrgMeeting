#include "../inc/common.h"

bn_t N;
bn_t N_1;
ep_t G;

void hash2bn(bn_t h, const uint8_t *msg, int len)
{
	uint8_t hash[32];
	md_map_sh256(hash, msg, len);
	bn_t tmp;
	bn_null(tmp);
	bn_new(tmp);
	bn_read_bin(tmp, hash, 32);
	bn_mod(h, tmp, N);
	bn_free(tmp);
}

void initGlobal()
{
	bn_null(N);
	bn_null(N_1);
	ep_null(G);
	bn_new(N);
	bn_new(N_1);
	ep_new(G);
	ep_curve_get_ord(N);
	bn_sub_dig(N_1, N, 1);
	ep_curve_get_gen(G);
}

void freeGlobal()
{
	bn_free(N);
	bn_free(N_1);
	ep_free(G);
}
