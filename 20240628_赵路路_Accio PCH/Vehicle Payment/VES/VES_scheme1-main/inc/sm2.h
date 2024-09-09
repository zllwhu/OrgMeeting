#ifndef SM2_H
#define SM2_H

#include "common.h"	

typedef struct
{
	ep_t P;
	bn_t d;
}SM2KeyPair_t;

void init_SM2KeyPair(SM2KeyPair_t *kp);

void free_SM2KeyPair(SM2KeyPair_t *kp);

/**
 * @brief 生成SM2公私钥对
*/
void genSM2KeyPair(SM2KeyPair_t *kp);


typedef struct
{
	bn_t r;
	bn_t s;
}SM2Sign_t;

/**
 * @brief 初始化SM2签名
*/
void init_SM2Sign_t(SM2Sign_t *sig);

/**
 * @brief 释放SM2公私钥对
 */
void free_SM2Sign_t(SM2Sign_t *sig);

/**
 * @brief 标准SM2签名
 * @param[out] sig 签名
 * @param[in] kp 签名者密钥对
 * @param[in] msg 消息
 * @param[in] mlen 消息的字节长度
 */
void sm2_sign(SM2Sign_t *sig, SM2KeyPair_t *kp, uint8_t *msg, int mlen);

/**
 * @brief SM2签名修改
 * @param[out] sig 签名
 * @param[in] kp 签名者密钥对
 * @param[in] msg 消息
 * @param[in] mlen 消息的字节长度
 * @param[out] K 签名过程计算的[k]G，用于可验证加密
 * @param[out] LSB_y [k]G y坐标的奇偶位，用于恢复K
*/
void sm2_signV2(SM2Sign_t *sig, SM2KeyPair_t *kp, uint8_t *msg, int mlen, ep_t K, int *LSB_y);

/**
 * @brief 标准SM2验签
 * @param[in] sig 签名
 * @param[in] P 签名者公钥
 * @param[in] msg 消息
 * @param[in] mlen 消息的字节长度
 * @return 1 验签通过; 0 验签失败
 */
int sm2_verify(SM2Sign_t *sig, ep_t P, uint8_t *msg, int mlen);

/**
 * @brief 根据x坐标和y的奇偶位恢复出椭圆曲线上的点P
 * @param[out] p 恢复出的点
 * @param[in] x x坐标
 * @param[in] LSB_y y坐标的奇偶位
*/
void upk_point(ep_t p, fp_t x, int LSB_y);

#endif