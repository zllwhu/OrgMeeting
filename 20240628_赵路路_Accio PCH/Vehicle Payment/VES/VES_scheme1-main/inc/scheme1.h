#ifndef SCHEME1_H
#define SCHEME1_H

#include "../inc/common.h"
#include "paillier.h"
#include "sm2.h"
#include "util.h"

/**
 * 方案一：基于Paillier加密的SM2签名判定的可验证加密方案
*/

typedef struct
{
	// 签名过程中[k]G的y坐标奇偶位，以便后续从x坐标恢复[k]G
	int lsb_y;
	bn_t r;
	bn_t C;
	// 零知识证明
	ep_t R1;
	bn_t R2;
	bn_t c;
	bn_t z1;
	bn_t z2;
}CipherText_st;

/**
 * @brief 初始化方案1密文
 */
void init_CipherText(CipherText_st *ct);

/**
 * @brief 释放方案1密文
*/
void free_CipherText(CipherText_st *ct);

/**
 * @brief 可验证加密算法（基于Paillier加密的SM2签名判定的可验证加密方案）
 * @param[out] ct 生成的密文
 * @param[in] kp SM2签名密钥对
 * @param[in] pub Paillier加密密钥
 * @param[in] msg 消息
 * @param[in] mlen 消息字节长度
 */
void veriableEnc(CipherText_st *ct, SM2KeyPair_t *kp, bn_t pub, uint8_t *msg, int mlen);

/**
 * @brief 加密验证算法（基于Paillier加密的SM2签名判定的可验证加密方案）
 * @param[in] ct 密文
 * @param[in] ec_pk SM2签名公钥
 * @param[in] pub Paillier加密密钥
 * @param[in] msg 消息
 * @param[in] mlen 消息字节长度
 * @return 1 验证通过; 0 验证失败
 */
int verify(CipherText_st *ct, ep_t ec_pk, bn_t pub, uint8_t *msg, int mlen);

/**
 * @brief 可验证解密算法（基于Paillier加密的SM2签名判定的可验证加密方案）
 * @param[out] sig 恢复出的SM2签名值
 * @param[in] ct 密文
 * @param[in] kp Paillier密钥对
 */
int veriableDec(SM2Sign_t *sig, CipherText_st *ct, PaillierKeyPair_t *kp);

void schemeInit();

void schemeFree();

void testScheme1();

#endif