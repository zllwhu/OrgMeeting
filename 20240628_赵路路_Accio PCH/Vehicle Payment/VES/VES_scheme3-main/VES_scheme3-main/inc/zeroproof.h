#ifndef ZERO_PROOF_H

#define ZERO_PROOF_H

#include "common.h"

/**
 * public parameters used in zero-knowledge proof
 */
typedef struct
{
    g2_t vk;
    g1_t sigma[u];
    g1_t T[u];
} CrsParam_st;

/**
 * zero-knowledge proof
 */
typedef struct
{
    bn_t R;

    g1_t V[l];
    g1_t a[l];
    g1_t W[l];

    bn_t c;

    bn_t z_v[l];
    bn_t z_s[l];

    bn_t z;
    g2_t theta;
    bn_t r_hat;
} ZkPi_st;

void ves_crsparam_init(CrsParam_st *crs);
void ves_crsparam_free(CrsParam_st *crs);

void ves_zkpi_init(ZkPi_st *crs);
void ves_zkpi_free(ZkPi_st *crs);

/**
 * @brief key generation of zero-knowledge proof
 *
 */
void nizk_k(CrsParam_st *crs);

/**
 * generation zero-knowledge proof
 */
void nizk_p(ZkPi_st *pi, const bn_t s, const bn_t mu, const CrsParam_st *crs, const bn_t N);

/**
 * validation of zero-knowledge proof
 */
int nizk_v(const bn_t C, const ZkPi_st *pi, const CrsParam_st *crs, const bn_t N);

#endif