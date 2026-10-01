/*
 * userlog.c - Securely append a username and log message to userlog.txt
 *
 * Usage:   ./userlog <username> <message>
 * Build:   gcc -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -O2 \
 *              -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
 *              -o userlog userlog.c
 *
 * Output line format (one entry per line):
 *   2026-10-01T14:03:27Z user=<username> msg=<message>
 *
 * Security measures:
 *   - Exact argument count check.
 *   - Length limits enforced with strnlen() (never reads past the limit).
 *   - Username restricted to a whitelist: [A-Za-z0-9._-], must not start with '-'.
 *   - Message rejects all control characters (CR, LF, TAB, ESC, NUL, DEL, ...),
 *     which prevents log injection / forged log lines and terminal escape attacks.
 *   - No strcpy/strcat/sprintf/gets/scanf; all formatting uses bounded snprintf()
 *     with truncation detection.
 *   - File opened with open(2) using O_APPEND | O_NOFOLLOW | O_CLOEXEC and
 *     mode 0600 under umask 077, so symlink attacks are refused and a newly
 *     created log is private to the owner.
 *   - fstat() verifies the target is a regular file (not a FIFO, device, etc.).
 *   - Exclusive advisory lock (flock) keeps concurrent writers from interleaving.
 *   - write() loop handles partial writes and EINTR; fsync() and close() are
 *     both checked so data loss is reported, not silently ignored.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE /* for flock() on glibc */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define LOG_FILENAME     "userlog.txt"
#define USERNAME_MAX_LEN 32U    /* maximum username length in bytes   */
#define MESSAGE_MAX_LEN  1024U  /* maximum message length in bytes    */
#define TIMESTAMP_LEN    sizeof("YYYY-MM-DDTHH:MM:SSZ")

/* Entry buffer: timestamp + " user=" + username + " msg=" + message + "\n" + NUL */
#define ENTRY_BUF_LEN (TIMESTAMP_LEN + sizeof(" user=") + USERNAME_MAX_LEN + \
                       sizeof(" msg=") + MESSAGE_MAX_LEN + 2U)

/*
 * validate_username - accept only 1..USERNAME_MAX_LEN characters from the
 * set [A-Za-z0-9._-]. A leading '-' is rejected so the value can never be
 * mistaken for an option by tools that later process the log.
 * Explicit range checks are used instead of isalnum() so the result does not
 * depend on the current locale.
 * Returns 0 if valid, -1 otherwise (with a message on stderr).
 */
static int validate_username(const char *username)
{
    size_t len;
    size_t i;

    if (username == NULL) {
        fprintf(stderr, "Error: username is missing.\n");
        return -1;
    }

    /* strnlen never scans more than USERNAME_MAX_LEN + 1 bytes. */
    len = strnlen(username, USERNAME_MAX_LEN + 1U);
    if (len == 0U) {
        fprintf(stderr, "Error: username must not be empty.\n");
        return -1;
    }
    if (len > USERNAME_MAX_LEN) {
        fprintf(stderr, "Error: username exceeds %u characters.\n",
                USERNAME_MAX_LEN);
        return -1;
    }
    if (username[0] == '-') {
        fprintf(stderr, "Error: username must not begin with '-'.\n");
        return -1;
    }

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)username[i];
        int ok = (c >= 'a' && c <= 'z') ||
                 (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') ||
                 c == '.' || c == '_' || c == '-';
        if (!ok) {
            fprintf(stderr,
                    "Error: username may contain only letters, digits, "
                    "'.', '_' and '-'.\n");
            return -1;
        }
    }
    return 0;
}

/*
 * validate_message - accept 1..MESSAGE_MAX_LEN bytes, rejecting every
 * control character (0x00-0x1F and 0x7F). This blocks newline-based log
 * forging and ANSI escape sequences. Bytes >= 0x80 are allowed so that
 * UTF-8 text (e.g. accented or non-Latin characters) can be logged.
 * A message consisting solely of spaces is rejected as meaningless.
 * Returns 0 if valid, -1 otherwise (with a message on stderr).
 */
static int validate_message(const char *message)
{
    size_t len;
    size_t i;
    int has_visible = 0;

    if (message == NULL) {
        fprintf(stderr, "Error: message is missing.\n");
        return -1;
    }

    len = strnlen(message, MESSAGE_MAX_LEN + 1U);
    if (len == 0U) {
        fprintf(stderr, "Error: message must not be empty.\n");
        return -1;
    }
    if (len > MESSAGE_MAX_LEN) {
        fprintf(stderr, "Error: message exceeds %u bytes.\n", MESSAGE_MAX_LEN);
        return -1;
    }

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)message[i];
        if (c < 0x20U || c == 0x7FU) {
            fprintf(stderr,
                    "Error: message contains a control character "
                    "(newlines, tabs and escapes are not allowed).\n");
            return -1;
        }
        if (c != ' ') {
            has_visible = 1;
        }
    }

    if (!has_visible) {
        fprintf(stderr, "Error: message must contain visible text.\n");
        return -1;
    }
    return 0;
}

/*
 * make_timestamp - write the current UTC time in ISO 8601 form into buf.
 * gmtime_r() is the thread-safe variant of gmtime().
 * Returns 0 on success, -1 on failure.
 */
static int make_timestamp(char *buf, size_t buflen)
{
    time_t now;
    struct tm tm_utc;

    now = time(NULL);
    if (now == (time_t)-1) {
        perror("Error: time");
        return -1;
    }
    if (gmtime_r(&now, &tm_utc) == NULL) {
        fprintf(stderr, "Error: could not convert time to UTC.\n");
        return -1;
    }
    /* strftime returns 0 if the result would not fit in buf. */
    if (strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0U) {
        fprintf(stderr, "Error: timestamp buffer too small.\n");
        return -1;
    }
    return 0;
}

/*
 * write_all - write exactly len bytes, retrying on partial writes and
 * on interruption by a signal (EINTR).
 * Returns 0 on success, -1 on failure.
 */
static int write_all(int fd, const char *data, size_t len)
{
    size_t written = 0U;

    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;           /* interrupted before writing: retry */
            }
            perror("Error: write");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "Error: write made no progress.\n");
            return -1;
        }
        written += (size_t)n;
    }
    return 0;
}

/*
 * append_entry - open (or create) the log file safely and append one line.
 * Returns 0 on success, -1 on failure. The file descriptor is always closed.
 */
static int append_entry(const char *entry, size_t entry_len)
{
    int fd;
    int status = -1;
    struct stat st;

    /*
     * O_APPEND   : every write goes to the current end of file.
     * O_CREAT    : create the file if it does not exist.
     * O_NOFOLLOW : fail if userlog.txt is a symlink (blocks symlink attacks).
     * O_CLOEXEC  : do not leak the descriptor into child processes.
     * 0600       : owner read/write only (further restricted by umask 077).
     */
    do {
        fd = open(LOG_FILENAME,
                  O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        if (errno == ELOOP) {
            fprintf(stderr, "Error: %s is a symbolic link; refusing to write.\n",
                    LOG_FILENAME);
        } else {
            perror("Error: open " LOG_FILENAME);
        }
        return -1;
    }

    /* Check the object we actually opened (no race with a separate stat()). */
    if (fstat(fd, &st) != 0) {
        perror("Error: fstat");
        goto out;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a regular file.\n", LOG_FILENAME);
        goto out;
    }

    /* Exclusive advisory lock so concurrent instances don't interleave. */
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            perror("Error: flock");
            goto out;
        }
    }

    if (write_all(fd, entry, entry_len) != 0) {
        goto out;
    }

    /* Make sure the data actually reaches the disk. */
    if (fsync(fd) != 0) {
        perror("Error: fsync");
        goto out;
    }

    status = 0;

out:
    /* close() also releases the flock. Its failure can mean lost data. */
    if (close(fd) != 0) {
        perror("Error: close");
        status = -1;
    }
    return status;
}

int main(int argc, char *argv[])
{
    char timestamp[TIMESTAMP_LEN];
    char entry[ENTRY_BUF_LEN];
    int n;

    /* Restrict permissions of any file this process creates. */
    (void)umask(S_IRWXG | S_IRWXO);

    /* Exactly two user-supplied arguments are required. */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <message>\n",
                (argc > 0 && argv[0] != NULL) ? argv[0] : "userlog");
        fprintf(stderr, "  Quote the message if it contains spaces.\n");
        return EXIT_FAILURE;
    }

    if (validate_username(argv[1]) != 0 || validate_message(argv[2]) != 0) {
        return EXIT_FAILURE;
    }

    if (make_timestamp(timestamp, sizeof(timestamp)) != 0) {
        return EXIT_FAILURE;
    }

    /*
     * Build the full line in one bounded buffer so it is written with a
     * single append. User data is only ever passed as %s arguments, never
     * as the format string, so format-string attacks are impossible.
     */
    n = snprintf(entry, sizeof(entry), "%s user=%s msg=%s\n",
                 timestamp, argv[1], argv[2]);
    if (n < 0) {
        fprintf(stderr, "Error: failed to format log entry.\n");
        return EXIT_FAILURE;
    }
    if ((size_t)n >= sizeof(entry)) {
        /* Should be unreachable given the validated lengths; checked anyway. */
        fprintf(stderr, "Error: log entry would be truncated.\n");
        return EXIT_FAILURE;
    }

    if (append_entry(entry, (size_t)n) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}