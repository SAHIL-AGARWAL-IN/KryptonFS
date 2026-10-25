/*
 * krypton_passphrase.c - Passphrase from the environment, terminal or stdin.
 */
#define _POSIX_C_SOURCE 200809L

#include "krypton/krypton_passphrase.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "krypton/krypton_crypto.h"

static bool read_line(int fd, char *buf, size_t cap, size_t *len)
{
    size_t n = 0;

    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);

        if (r <= 0 || c == '\n')
            break;
        if (n + 1 >= cap)
            return false;
        buf[n++] = c;
    }
    if (n > 0 && buf[n - 1] == '\r')
        n--;
    buf[n] = '\0';
    *len = n;
    return true;
}

static bool prompt_tty(int tty, const char *prompt, char *buf, size_t cap, size_t *len)
{
    struct termios old, quiet;
    bool ok;

    if (tcgetattr(tty, &old) != 0)
        return false;
    quiet = old;
    quiet.c_lflag &= ~(tcflag_t)ECHO;
    if (write(tty, prompt, strlen(prompt)) < 0 || tcsetattr(tty, TCSAFLUSH, &quiet) != 0)
        return false;
    ok = read_line(tty, buf, cap, len);
    tcsetattr(tty, TCSAFLUSH, &old);
    if (write(tty, "\n", 1) < 0)
        ok = false;
    return ok;
}

kfs_status kfs_read_passphrase(const char *prompt, bool confirm,
                               char *buf, size_t cap, size_t *len)
{
    const char *env = getenv("KRYPTONFS_PASSPHRASE");
    int tty;
    bool ok;

    if (env != NULL) {
        size_t n = strlen(env);

        if (n + 1 > cap)
            return KFS_E_INVAL;
        memcpy(buf, env, n + 1);
        *len = n;
        unsetenv("KRYPTONFS_PASSPHRASE");
    } else if ((tty = open("/dev/tty", O_RDWR | O_CLOEXEC)) >= 0) {
        ok = prompt_tty(tty, prompt, buf, cap, len);
        if (ok && confirm) {
            char again[KFS_PASSPHRASE_MAX];
            size_t again_len = 0;

            ok = prompt_tty(tty, "Repeat passphrase: ", again, sizeof(again), &again_len) &&
                 again_len == *len && memcmp(again, buf, *len) == 0;
            kfs_wipe(again, sizeof(again));
            if (!ok)
                fprintf(stderr, "passphrases do not match\n");
        }
        close(tty);
        if (!ok) {
            kfs_wipe(buf, cap);
            return KFS_E_INVAL;
        }
    } else if (!read_line(STDIN_FILENO, buf, cap, len)) {
        kfs_wipe(buf, cap);
        return KFS_E_INVAL;
    }
    if (*len == 0) {
        fprintf(stderr, "empty passphrase\n");
        return KFS_E_INVAL;
    }
    return KFS_OK;
}
