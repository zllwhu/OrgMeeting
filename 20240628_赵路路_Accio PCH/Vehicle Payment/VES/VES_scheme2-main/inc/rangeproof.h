#ifndef RANGEPROOF_H
#define RANGEPROOF_H

#include "sm2.h"
#include "common.h"
#include "twisted_elgamal.h"
#include "../bulletproof/bp_interface.h"

void range_prove(uint32_t *s_arr, bn_t *rho_arr, size_t range_len, size_t agg_num, char *bf_file);

int range_verify(uint8_t *u_l, size_t range_len, size_t agg_num, char *bf_file);

#endif