#ifndef SCHEME3_H
#define SCHEME3_H

#include "paillier.h"
#include "common.h"
#include "util.h"
#include "zeroproof.h"

/**
 * 方案三：基于Paillier加密的数额判定的可验证加密方案
*/

typedef struct
{
	bn_t C;

	ZkPi_st pi;
} CipherText_st;

void ves_ciphertext_init(CipherText_st *ct);
void ves_ciphertext_free(CipherText_st *ct);

/**
 * @brief Verifiable encryption
 */
void ves_enc_s3(CipherText_st *ct, const bn_t N, const bn_t s, const CrsParam_st *cp);

/**
 * @brief Verifiable encryption-validation
 */
int ves_vrf_s3(const CipherText_st *ct, const bn_t N, const CrsParam_st *cp);

/**
 * @brief Verifiable encryption-decryption
 */
void ves_dec_s3(bn_t s, const CipherText_st *ct, const bn_t lambda, const bn_t N);

void test_scheme_3();

#endif