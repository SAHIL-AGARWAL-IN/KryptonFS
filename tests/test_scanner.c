/*
 * test_scanner.c - ELF detection, multi-pattern matching and signature
 * database parsing. All patterns are arbitrary placeholder bytes.
 */
#include "krypton/krypton_scanner.h"

#include "kfs_test.h"

static kfs_scanner *compiled_with(const char *db)
{
    kfs_scanner *sc = kfs_scanner_new();
    char err[256] = "";

    CHECK(sc != NULL);
    if (sc == NULL)
        return NULL;
    CHECK_EQ(kfs_scanner_parse(sc, db, strlen(db), err, sizeof(err)), KFS_OK);
    if (err[0] != '\0')
        fprintf(stderr, "%s\n", err);
    CHECK_EQ(kfs_scanner_compile(sc), KFS_OK);
    return sc;
}

static kfs_status scan_str(const kfs_scanner *sc, const char *s, kfs_scan_hit *hit)
{
    return kfs_scanner_scan(sc, (const uint8_t *)s, strlen(s), 4096, false, hit);
}

static void test_elf_header(void)
{
    static const uint8_t elf[] = { 0x7f, 'E', 'L', 'F', 2, 1, 1, 0 };
    kfs_scanner *sc = compiled_with("");
    kfs_scan_hit hit = { 99, 99 };

    if (sc == NULL)
        return;
    CHECK_EQ(kfs_scanner_scan(sc, elf, sizeof(elf), 0, true, &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, KFS_SIG_ELF_HEADER);
    CHECK_EQ(hit.offset, 0);
    CHECK_STR(kfs_scanner_sig_name(sc, KFS_SIG_ELF_HEADER), "ELF executable header");

    /* Only the first block of a file can hold the header ... */
    CHECK_EQ(kfs_scanner_scan(sc, elf, sizeof(elf), 4096, true, &hit), KFS_OK);
    /* ... and the check can be switched off. */
    CHECK_EQ(kfs_scanner_scan(sc, elf, sizeof(elf), 0, false, &hit), KFS_OK);
    CHECK_EQ(kfs_scanner_scan(sc, elf, 3, 0, true, &hit), KFS_OK);
    kfs_scanner_free(sc);
}

static void test_match_positions(void)
{
    /* 54455354 = "TEST", 51525354 = "QRST" */
    kfs_scanner *sc = compiled_with("10 54455354 test marker\n"
                                    "11 51525354\n");
    kfs_scan_hit hit;

    if (sc == NULL)
        return;
    CHECK_EQ(scan_str(sc, "TEST at start", &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, 10);
    CHECK_EQ(hit.offset, 0);

    CHECK_EQ(scan_str(sc, "in the middle QRST here", &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, 11);
    CHECK_EQ(hit.offset, 14);

    CHECK_EQ(scan_str(sc, "ends with TEST", &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.offset, 10);

    CHECK_EQ(scan_str(sc, "tes TES TEsT QRS RST", &hit), KFS_OK);
    CHECK_EQ(kfs_scanner_scan(sc, NULL, 0, 0, true, &hit), KFS_OK);

    CHECK_STR(kfs_scanner_sig_name(sc, 10), "test marker");
    CHECK_STR(kfs_scanner_sig_name(sc, 11), "unnamed signature");
    CHECK_STR(kfs_scanner_sig_name(sc, 12), "unknown signature");
    kfs_scanner_free(sc);
}

static void test_failure_links(void)
{
    /* "xabcdy" and "abcd": scanning "xabcdz" walks the long pattern's
     * branch, so "abcd" is only found through the failure link. Then
     * "aaab" exercises a fail chain after a run of repeated bytes. */
    kfs_scanner *sc = compiled_with("1 786162636479\n"
                                    "2 61626364\n"
                                    "3 61616162\n");
    kfs_scan_hit hit;

    if (sc == NULL)
        return;
    CHECK_EQ(scan_str(sc, "xabcdz", &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, 2);
    CHECK_EQ(hit.offset, 1);

    CHECK_EQ(scan_str(sc, "aaaaaab", &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, 3);
    CHECK_EQ(hit.offset, 3);

    CHECK_EQ(scan_str(sc, "xabcdy", &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, 2); /* earliest-ending match wins */
    kfs_scanner_free(sc);
}

static void test_binary_patterns(void)
{
    kfs_scanner *sc = compiled_with("# placeholder binary signature\n"
                                    "  500   00ff00ffA5   binary sample  \r\n");
    uint8_t block[4096];
    kfs_scan_hit hit;

    if (sc == NULL)
        return;
    memset(block, 0, sizeof(block));
    CHECK_EQ(kfs_scanner_scan(sc, block, sizeof(block), 0, true, &hit), KFS_OK);

    block[4091] = 0x00;
    block[4092] = 0xff;
    block[4093] = 0x00;
    block[4094] = 0xff;
    block[4095] = 0xa5;
    CHECK_EQ(kfs_scanner_scan(sc, block, sizeof(block), 0, true, &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, 500);
    CHECK_EQ(hit.offset, 4091);
    CHECK_STR(kfs_scanner_sig_name(sc, 500), "binary sample");
    kfs_scanner_free(sc);
}

static void test_api_misuse(void)
{
    static const uint8_t pat[] = { 1, 2, 3, 4 };
    kfs_scanner *sc = kfs_scanner_new();
    kfs_scan_hit hit;

    CHECK(sc != NULL);
    if (sc == NULL)
        return;
    CHECK_EQ(kfs_scanner_scan(sc, pat, sizeof(pat), 0, true, &hit), KFS_E_INVAL); /* not compiled */
    CHECK_EQ(kfs_scanner_add(sc, 0, NULL, pat, sizeof(pat)), KFS_E_INVAL);      /* reserved id */
    CHECK_EQ(kfs_scanner_add(sc, 1, NULL, pat, 3), KFS_E_INVAL);                /* too short */
    CHECK_EQ(kfs_scanner_add(sc, 1, NULL, pat, sizeof(pat)), KFS_OK);
    CHECK_EQ(kfs_scanner_compile(sc), KFS_OK);
    CHECK_EQ(kfs_scanner_add(sc, 2, NULL, pat, sizeof(pat)), KFS_E_INVAL);      /* frozen */
    kfs_scanner_free(sc);
    kfs_scanner_free(NULL);
}

static void expect_db_error(const char *db, const char *fragment)
{
    kfs_scanner *sc = kfs_scanner_new();
    char err[256] = "";

    CHECK(sc != NULL);
    if (sc == NULL)
        return;
    CHECK(kfs_scanner_parse(sc, db, strlen(db), err, sizeof(err)) != KFS_OK);
    if (strstr(err, fragment) == NULL) {
        fprintf(stderr, "error \"%s\" lacks \"%s\"\n", err, fragment);
        kfs_test_failures++;
    }
    kfs_scanner_free(sc);
}

static void test_db_errors(void)
{
    expect_db_error("0 54455354\n", "line 1: '0' is not a signature id");
    expect_db_error("\nabc 54455354\n", "line 2: 'abc' is not a signature id");
    expect_db_error("1 544553\n", "pattern must be 4..256 bytes");
    expect_db_error("1 5445535\n", "pattern must be");
    expect_db_error("1 5445535Z\n", "pattern must be");
    expect_db_error("1\n", "pattern must be");
}

static void test_load_missing_file(void)
{
    kfs_scanner *sc = kfs_scanner_new();
    char err[256] = "";

    CHECK(sc != NULL);
    if (sc == NULL)
        return;
    CHECK_EQ(kfs_scanner_load(sc, "/nonexistent/kryptonfs.sigs", err, sizeof(err)), KFS_E_IO);
    CHECK(strstr(err, "/nonexistent/kryptonfs.sigs") != NULL);
    kfs_scanner_free(sc);
}

int main(void)
{
    RUN(test_elf_header);
    RUN(test_match_positions);
    RUN(test_failure_links);
    RUN(test_binary_patterns);
    RUN(test_api_misuse);
    RUN(test_db_errors);
    RUN(test_load_missing_file);
    TEST_EXIT();
}
