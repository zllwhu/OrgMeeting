#ifndef TWISTED_ELGAMAL_H
#define TWISTED_ELGAMAL_H

#include "common.h"
#include <assert.h>

// hash表的最大偏移位（经实验测试）
#define PRE_COMPUTE_MAX_OFFSETS 7

// 根据SM2基点G派生成的Twisted_ElGamal
extern ep_t G1;
extern ep_t G2;

/**
 * @brief 初始化Twisted_ElGamal系统参数，即G1 G2
*/
void init_twisted_elgamal_PP();

/**
 * @brief 释放Twisted_ElGamal系统参数
*/
void free_twisted_elgamal_PP();

// Twisted_ElGamal加密密钥对
typedef struct
{
	ep_t T;
	bn_t t;
}Twisted_KeyPair_t;

void init_TwistedKeyPair(Twisted_KeyPair_t *kp);

void free_TwistedKeyPair(Twisted_KeyPair_t *kp);

/**
 * @brief 生成Twisted_ElGamal公私钥对
*/
void genTwistedKeyPair(Twisted_KeyPair_t *kp);

typedef struct
{
	uint16_t offset[PRE_COMPUTE_MAX_OFFSETS];
	uint8_t offset_count;
	uint8_t x_coordinate[32];
} PRE_COMPUTE_TABLE;

/**
 * @brief 生成g的预计算表
*/
int gen_pre_compute_table(PRE_COMPUTE_TABLE table[1 << 16], ep_t g);

/**
 * @brief 求解ECDLP问题
 * @param[in] table 预计算表
 * @param[in] SP 需要求解的点 SP = [x]P
 * @param[in] P 基点P
 * @param[out] x 标量x
 */
int solve_ecdlp(const PRE_COMPUTE_TABLE table[1 << 16], ep_t SP, ep_t P, uint32_t *x);

/**
 * @brief Twisted ElGamal加密
 * @param[out] U U = [m]G1 + [beta]G2
 * @param[out] V V = [beta]T
 * @param[in] T 公钥
 * @param[in] msg 消息m
*/
void twisted_elgamal_enc(ep_t U, ep_t V, ep_t T, uint32_t msg);

/**
 * @brief Twisted ElGamal加密（指定加密时使用的随机数）
 * @param[out] U U = [m]G1 + [beta]G2
 * @param[out] V V = [beta]T
 * @param[in] T 公钥
 * @param[in] msg 消息m
 * @param[in] beta 加密时使用的随机数
*/
void twisted_elgamal_encV2(ep_t U, ep_t V, ep_t T, uint32_t msg, bn_t beta);

/**
 * @brief Twisted ElGamal解密
 * @param[in] table G1的预计算表
 * @param[in] U U = [m]G1 + [beta]G2
 * @param[in] V V = [beta]T
 * @param[in] t 私钥
 * @param[out] m 消息m
*/
void twisted_elgamal_dec(const PRE_COMPUTE_TABLE table[1 << 16], ep_t U, ep_t V, bn_t t, uint32_t *m);

#endif