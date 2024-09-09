#ifndef BP_H
#define BP_H

#ifdef __cplusplus
extern "C" {
#endif

	void call_rangeprove(size_t range_len, size_t agg_num, uint8_t *g1x, uint8_t g1y, uint32_t *s_arr, uint8_t *rho_l, char *bf_file);

	int call_rangeverify(size_t range_len, size_t agg_num, uint8_t *g1x, uint8_t g1y, uint8_t *u_l, char *bf_file);

	void print_rangeproof(size_t range_len, size_t agg_num, char *bf_file);

#ifdef __cplusplus
}
#endif

#endif