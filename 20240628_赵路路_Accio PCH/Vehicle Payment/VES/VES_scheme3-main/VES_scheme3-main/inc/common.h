#ifndef COMMON_H
#define COMMON_H

#include "relic.h"

#define u_len 10
#define u (1 << u_len)
#define l 3

extern bn_t N_Tidle;
extern bn_t N_Tidle_Sub1;
extern g1_t G1;
extern g2_t G2;

/**
 * @brief initialize core, fp_prime, ep_curve, global variable
 */
void ves_init();

/**
 * @brief free global variable, ep_curve, fp_prime, core
 */
void ves_free();

/**
 * @brief hash to filed
 */
void hash2bn(bn_t bn, const uint8_t *bytes, int len);

#endif