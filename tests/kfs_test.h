/*
 * kfs_test.h - Minimal assertion harness for KryptonFS unit tests.
 *
 * Each test binary is one CTest case: RUN() every test function, then
 * TEST_EXIT() returns nonzero if any CHECK failed.
 */
#ifndef KFS_TEST_H
#define KFS_TEST_H

#include <stdio.h>
#include <string.h>

static int kfs_test_failures;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n",                 \
                    __FILE__, __LINE__, #cond);                          \
            kfs_test_failures++;                                         \
        }                                                                \
    } while (0)

#define CHECK_EQ(a, b)                                                   \
    do {                                                                 \
        unsigned long long a_ = (unsigned long long)(a);                 \
        unsigned long long b_ = (unsigned long long)(b);                 \
        if (a_ != b_) {                                                  \
            fprintf(stderr, "%s:%d: CHECK_EQ(%s, %s) failed: %llu != %llu\n", \
                    __FILE__, __LINE__, #a, #b, a_, b_);                 \
            kfs_test_failures++;                                         \
        }                                                                \
    } while (0)

#define CHECK_STR(a, b)                                                  \
    do {                                                                 \
        const char *a_ = (a), *b_ = (b);                                 \
        if (strcmp(a_, b_) != 0) {                                       \
            fprintf(stderr, "%s:%d: CHECK_STR(%s, %s) failed: \"%s\" != \"%s\"\n", \
                    __FILE__, __LINE__, #a, #b, a_, b_);                 \
            kfs_test_failures++;                                         \
        }                                                                \
    } while (0)

#define RUN(test)                                                        \
    do {                                                                 \
        int before_ = kfs_test_failures;                                 \
        test();                                                          \
        printf("%s %s\n", kfs_test_failures == before_ ? "PASS" : "FAIL", #test); \
    } while (0)

#define TEST_EXIT() return kfs_test_failures == 0 ? 0 : 1

#endif /* KFS_TEST_H */
