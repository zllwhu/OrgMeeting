#include "../inc/rangeproof.h"


void range_prove(uint32_t *s_arr, bn_t *rho_arr, size_t range_len, size_t agg_num, char *bf_file)
{
	uint8_t g1x[32], g1y;
	bn_t coor;
	bn_new(coor);
	fp_prime_back(coor, G1->x);
	bn_write_bin(g1x, 32, coor);
	fp_prime_back(coor, G1->y);
	g1y = bn_get_bit(coor, 0);
	bn_free(coor);
	uint8_t *rho_l = (uint8_t *)malloc(sizeof(uint8_t) * 32 * agg_num);
	for (int i = 0; i < agg_num; i++)
	{
		bn_write_bin(rho_l + i * 32, 32, rho_arr[i]);
	}
	call_rangeprove(range_len, agg_num, g1x, g1y, s_arr, rho_l, bf_file);
	free(rho_l);
}

int range_verify(uint8_t *u_l, size_t range_len, size_t agg_num, char *bf_file)
{
	int ret;
	uint8_t g1x[32], g1y;
	bn_t coor;
	bn_new(coor);
	fp_prime_back(coor, G1->x);
	bn_write_bin(g1x, 32, coor);
	fp_prime_back(coor, G1->y);
	g1y = bn_get_bit(coor, 0);
	bn_free(coor);

	ret = call_rangeverify(range_len, agg_num, g1x, g1y, u_l, bf_file);
	return ret;
}
// void 