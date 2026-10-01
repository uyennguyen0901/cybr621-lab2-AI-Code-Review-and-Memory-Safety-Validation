#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define LOG_FILE "userlog.txt"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <username> <log message>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *username = argv[1];
    if (username[0] == '\0') {
        fprintf(stderr, "Error: username must not be empty\n");
        return EXIT_FAILURE;
    }

    /* Build a timestamp */
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (now == (time_t)-1 || tm_info == NULL ||
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
        strcpy(timestamp, "unknown-time");
    }

    FILE *fp = fopen(LOG_FILE, "a");
    if (fp == NULL) {
        fprintf(stderr, "Error opening %s: %s\n", LOG_FILE, strerror(errno));
        return EXIT_FAILURE;
    }

    if (fprintf(fp, "[%s] %s: ", timestamp, username) < 0) {
        fprintf(stderr, "Error writing to %s: %s\n", LOG_FILE, strerror(errno));
        fclose(fp);
        return EXIT_FAILURE;
    }

    /* Join all remaining arguments as the message, replacing newlines
       so each entry stays on a single line */
    for (int i = 2; i < argc; i++) {
        for (const char *p = argv[i]; *p != '\0'; p++) {
            int c = (*p == '\n' || *p == '\r') ? ' ' : (unsigned char)*p;
            if (fputc(c, fp) == EOF) {
                fprintf(stderr, "Error writing to %s: %s\n", LOG_FILE, strerror(errno));
                fclose(fp);
                return EXIT_FAILURE;
            }
        }
        if (i < argc - 1 && fputc(' ', fp) == EOF) {
            fprintf(stderr, "Error writing to %s: %s\n", LOG_FILE, strerror(errno));
            fclose(fp);
            return EXIT_FAILURE;
        }
    }

    if (fputc('\n', fp) == EOF) {
        fprintf(stderr, "Error writing to %s: %s\n", LOG_FILE, strerror(errno));
        fclose(fp);
        return EXIT_FAILURE;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "Error closing %s: %s\n", LOG_FILE, strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}