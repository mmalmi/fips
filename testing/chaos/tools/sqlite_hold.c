/* Test-only write contention. No SQL data changes; release also has a deadline. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;

static void stop(int signal_number) {
    (void)signal_number;
    stopped = 1;
}

static double now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: sqlite-hold EXISTING_DB RELEASE_FILE MAX_SECONDS\n");
        return 1;
    }
    char *end;
    unsigned long seconds = strtoul(argv[3], &end, 10);
    if (*argv[3] == '\0' || *end != '\0' || seconds < 1 || seconds > 180 ||
        access(argv[2], F_OK) == 0 || errno != ENOENT) {
        fprintf(stderr, "invalid deadline or release file\n");
        return 1;
    }
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(argv[1], &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        fprintf(stderr, "cannot open existing test database\n");
        sqlite3_close(db);
        return 1;
    }
    sqlite3_busy_timeout(db, 2000);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "cannot acquire test write transaction\n");
        sqlite3_close(db);
        return 1;
    }
    printf("{\"locked\":true,\"pid\":%ld}\n", (long)getpid());
    fflush(stdout);
    double deadline = now() + (double)seconds;
    const char *reason = "deadline";
    while (now() < deadline) {
        if (stopped) {
            reason = "signal";
            break;
        }
        if (access(argv[2], F_OK) == 0) {
            reason = "requested";
            break;
        }
        if (errno != ENOENT) {
            reason = "release_error";
            break;
        }
        struct timespec pause = {0, 20000000};
        nanosleep(&pause, NULL);
    }
    int result = sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    int closed = sqlite3_close(db);
    if (result != SQLITE_OK || closed != SQLITE_OK) {
        fprintf(stderr, "test transaction rollback failed\n");
        return 1;
    }
    printf("{\"released\":true,\"reason\":\"%s\"}\n", reason);
    return 0;
}
