#ifndef PAILLIER_H
#define PAILLIER_H

#include "common.h"

typedef struct
{
	bn_t pub;
	bn_t prv;
}PaillierKeyPair_t;

/**
 * @brief initiate Paillier key pair
 */
void init_paillier_key_pair(PaillierKeyPair_t *kp);

/**
 * @brief free Paillier key pair
*/
void free_paillier_key_pair(PaillierKeyPair_t *kp);

/**
 * @brief generate Paillier key pair
*/
void gen_paillier_key_pair(PaillierKeyPair_t *kp, int blen);

/**
 * @brief paillier encrypt
 */
void paillier_enc(bn_t c, const bn_t pub, const bn_t m, const bn_t r);

#define VesKeyPair PaillierKeyPair_t 

#define ves_key_pair_init init_paillier_key_pair
#define ves_key_pair_free free_paillier_key_pair
#define ves_gen_key_pair gen_paillier_key_pair
#define ves_paillier_enc paillier_enc

#endif