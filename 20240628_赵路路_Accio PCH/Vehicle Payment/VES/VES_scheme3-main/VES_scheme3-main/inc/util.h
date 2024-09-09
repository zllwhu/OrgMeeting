#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <time.h>

#define BENCH_TEST(times, code, test_item)                                \
    do                                                        \
    {                                                         \
        clock_t start, end;                                   \
        double elapsed;                                       \
        start = clock();                                      \
        for (int i = 0; i < times; ++i)                       \
        {                                                     \
            code;                                             \
        }                                                     \
        end = clock();                                        \
        elapsed = ((double) (end - start)) * 1000.0 / CLOCKS_PER_SEC;\ 	
printf("\n+=======================================+\n");\
printf("%s Bench Test:\n", test_item);\
printf("Time taken for %d loops: %.2f ms\n", times, elapsed);\
printf("+=======================================+\n");\
	} while (0)

#endif