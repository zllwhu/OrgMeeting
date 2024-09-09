#ifndef PAILLIER_H
#define PAILLIER_H

#include "common.h"

typedef struct
{
	bn_t pub;
	bn_t prv;
}PaillierKeyPair_t;

/**
 * @brief 初始化Paillier密钥对
 */
void init_PaillierKeyPair(PaillierKeyPair_t *kp);

/**
 * @brief 释放Paillier密钥对
*/
void free_PaillierKeyPair(PaillierKeyPair_t *kp);

/**
 * @brief 生成Paillier密钥对
*/
void gen_PaillierKeyPair(PaillierKeyPair_t *kp, int blen);

/**
 * @brief paillier加密修改
 * @param[out] c 密文
 * @param[in] pub 公钥
 * @param[in] m 明文
 * @param[in] r 加密时使用的随机数
 */
void paillier_enc(bn_t c, bn_t pub, bn_t m, bn_t r);

#endif