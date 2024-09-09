#pragma once
#ifndef COMMON_H
#define COMMON_H

#include "relic.h"
#include "relic_bn.h"
#include "relic_ep.h"
#include <stdio.h>
#include <stdlib.h>

extern bn_t N;
extern bn_t N_1;
extern ep_t G;

/**
 * @brief 将Hash值转换成bn_t
*/
void hash2bn(bn_t h, const uint8_t *msg, int len);

/**
 * @brief 初始化所需的全局变量
*/
void initGlobal();

/**
 * @brief 释放全局变量
*/
void freeGlobal();



#endif

