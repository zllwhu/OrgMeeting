#include <stdio.h>

#include "relic.h"
#include "relic_ep.h"
#include "../inc/common.h"

/**
 * @brief The order of G1, G2 or GT
 */
bn_t N_Tidle;

/**
 * @brief N_Tidle sub 1
 */
bn_t N_Tidle_Sub1;

void ves_init()
{
	core_init();
	fp_prime_init();
	ep_curve_init();
	pp_map_init();
	pc_core_init();

	fp_param_set(B12_381);
	ep_param_set(B12_P381);
	ep2_curve_set_twist(RLC_EP_MTYPE);

	bn_null(N_Tidle);
	bn_null(N_Tidle_Sub1);

	bn_new(N_Tidle);
	bn_new(N_Tidle_Sub1);

	pc_get_ord(N_Tidle);
	bn_sub_dig(N_Tidle_Sub1, N_Tidle, 1);
}

void ves_free()
{
	bn_free(N_Tidle);
	bn_free(N_Tidle_Sub1);

	pc_core_clean;
	pp_map_clean();
	ep_curve_clean();
	fp_prime_clean();
	core_clean();
}

void hash2bn(bn_t bn, const uint8_t *bytes, int len)
{
	uint8_t hash[32];

	md_map_sh256(hash, bytes, len);
	bn_read_bin(bn, hash, 32);

	bn_mod(bn, bn, N_Tidle);
}