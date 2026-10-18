/* Test-only write contention. No SQL data changes; release also has a deadline. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int expired(void *deadline) {
    return now() > *(double *)deadline;
}

/* A bounded snapshot of caller-pinned public identities, never arbitrary SQL. */
static int observe(const char *path) {
    unsigned char ys[1024][33];
    int count = 0, states[1024], result = 1;
    char line[68];
    while (fgets(line, sizeof(line), stdin)) {
        if (count == 1024 || strlen(line) != 67 || line[66] != '\n')
            return 1;
        for (int i = 0; i < 33; i++) {
            unsigned value = 0;
            for (int j = 0; j < 2; j++) {
                char ch = line[2 * i + j];
                if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
                    return 1;
                value = value * 16 + (unsigned)(ch <= '9' ? ch - '0' : ch - 'a' + 10);
            }
            ys[count][i] = (unsigned char)value;
        }
        for (int i = 0; i < count; i++)
            if (memcmp(ys[i], ys[count], 33) == 0) return 1;
        count++;
    }
    if (count == 0 || ferror(stdin)) return 1;
    sqlite3 *db = NULL;
    sqlite3_stmt *query = NULL;
    const char *names[] = {"UNSPENT", "SPENT", "PENDING_SPENT", "PENDING", "RESERVED"};
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_db_readonly(db, "main") != 1) goto done;
    sqlite3_busy_timeout(db, 250);
    double deadline = now() + 1;
    sqlite3_progress_handler(db, 100, expired, &deadline);
    if (sqlite3_exec(db, "PRAGMA query_only=ON; BEGIN", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, "SELECT state FROM proof WHERE y=?1", -1, &query, NULL) != SQLITE_OK)
        goto done;
    for (int i = 0; i < count; i++) {
        if (now() > deadline || sqlite3_bind_blob(query, 1, ys[i], 33, SQLITE_STATIC) != SQLITE_OK)
            goto done;
        int step = sqlite3_step(query);
        states[i] = -1;
        if (step == SQLITE_ROW) {
            const unsigned char *state = sqlite3_column_text(query, 0);
            for (int j = 0; state && j < 5; j++)
                if (strcmp((const char *)state, names[j]) == 0) states[i] = j;
            if (states[i] == -1 || sqlite3_step(query) != SQLITE_DONE) goto done;
        } else if (step != SQLITE_DONE) goto done;
        if (sqlite3_reset(query) != SQLITE_OK) goto done;
    }
    if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) goto done;
    printf("{\"states\":[");
    for (int i = 0; i < count; i++) {
        if (i) putchar(',');
        if (states[i] == -1) printf("null");
        else printf("\"%s\"", names[states[i]]);
    }
    puts("]}");
    result = 0;
done:
    sqlite3_finalize(query);
    sqlite3_close(db);
    if (result) fprintf(stderr, "bounded read-only proof observation failed\n");
    return result;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "observe") == 0) return observe(argv[2]);
    if (argc != 4) {
        fprintf(stderr, "usage: sqlite-hold EXISTING_DB RELEASE_FILE MAX_SECONDS\n");
        return 1;
    }
    char *end;
    unsigned long seconds = strtoul(argv[3], &end, 10);
    if (*argv[3] == '\0' || *end != '\0' || seconds < 1 || seconds > 420 ||
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
