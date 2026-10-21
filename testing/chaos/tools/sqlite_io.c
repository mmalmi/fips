/* Unfunded diagnostic: concurrent SQLite WAL commits and atomic journal writes. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ROWS 5480
#define BATCH 128
#define SAMPLE_CAP 4096
static volatile sig_atomic_t interrupted;
static atomic_bool writing;
static int directory;
static uint64_t journal_samples[SAMPLE_CAP], commit_samples[SAMPLE_CAP];
static unsigned journals, commits;

static void stop(int signal_number) { (void)signal_number; interrupted = 1; }
static void require(int valid, const char *message) {
    if (!valid) { perror(message); exit(1); }
}
static uint64_t now(void) {
    struct timespec value;
    require(clock_gettime(CLOCK_MONOTONIC, &value) == 0, "clock");
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}
static void sql(sqlite3 *db, const char *text) {
    char *error = NULL;
    if (sqlite3_exec(db, text, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "SQLite: %s\n", error ? error : sqlite3_errmsg(db));
        sqlite3_free(error); exit(1);
    }
}
static void *journal(void *unused) {
    (void)unused;
    char bytes[2048]; memset(bytes, 'j', sizeof(bytes));
    while (atomic_load(&writing) && !interrupted && journals < SAMPLE_CAP) {
        uint64_t started = now();
        int fd = openat(directory, "journal.pending", O_CREAT | O_EXCL | O_WRONLY, 0600);
        require(fd >= 0, "create journal");
        size_t offset = 0;
        while (offset < sizeof(bytes)) {
            ssize_t count = write(fd, bytes + offset, sizeof(bytes) - offset);
            if (count < 0 && errno == EINTR) continue;
            require(count > 0, "write journal"); offset += (size_t)count;
        }
        require(fsync(fd) == 0 && close(fd) == 0, "sync journal");
        require(renameat(directory, "journal.pending", directory, "journal.json") == 0,
                "rename journal");
        require(fsync(directory) == 0, "sync journal directory");
        journal_samples[journals++] = now() - started;
        struct timespec delay = {0, 100000000}; nanosleep(&delay, NULL);
    }
    return NULL;
}
static void rows(sqlite3 *db, sqlite3_stmt *statement, unsigned first, unsigned last,
                 unsigned cycle) {
    unsigned char bytes[3072] = {0};
    for (unsigned id = first; id < last; id++) {
        uint32_t random = id + cycle * ROWS;
        /* A bounded amount of incompressible data; this contains no financial material. */
        for (unsigned i = 0; i < 256; i++) {
            random = random * 1664525U + 1013904223U;
            bytes[i] = (unsigned char)(random >> 24);
        }
        require(sqlite3_bind_int(statement, 1, (int)id) == SQLITE_OK, "bind id");
        require(sqlite3_bind_blob(statement, 2, bytes, sizeof(bytes), SQLITE_TRANSIENT) == SQLITE_OK,
                "bind payload");
        if (sqlite3_step(statement) != SQLITE_DONE) {
            fprintf(stderr, "SQLite row: %s\n", sqlite3_errmsg(db)); exit(1);
        }
        require(sqlite3_reset(statement) == SQLITE_OK, "reset row");
    }
}
static int compare(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static void statistics(const char *label, uint64_t *values, unsigned count) {
    require(count > 0, "missing samples");
    qsort(values, count, sizeof(*values), compare);
    unsigned p95 = (95U * count + 99U) / 100U - 1U;
    printf("\"%s\":{\"count\":%u,\"p95_ns\":%llu,\"maximum_ns\":%llu}",
           label, count, (unsigned long long)values[p95], (unsigned long long)values[count - 1]);
}
int main(int argc, char **argv) {
    if (argc != 4 || argv[1][0] != '/' || strlen(argv[1]) > 180) {
        fprintf(stderr, "usage: sqlite-io ABSENT_PRIVATE_DIRECTORY WAL_FRAMES|baseline SECONDS\n"); return 1;
    }
    char *end = NULL;
    unsigned long frames = 0;
    if (strcmp(argv[2], "baseline") != 0) {
        frames = strtoul(argv[2], &end, 10);
        require(*argv[2] && !*end && frames >= 16 && frames <= 4096, "invalid WAL frames");
    }
    unsigned long seconds = strtoul(argv[3], &end, 10);
    require(*argv[3] && !*end && seconds >= 1 && seconds <= 30, "invalid duration");
    umask(0077);
    require(mkdir(argv[1], 0700) == 0, "directory must not exist");
    directory = open(argv[1], O_RDONLY | O_DIRECTORY);
    require(directory >= 0, "open directory");
    int marker = openat(directory, "NONFINANCIAL_DIAGNOSTIC", O_CREAT | O_EXCL | O_WRONLY, 0600);
    require(marker >= 0 && close(marker) == 0, "create marker");
    signal(SIGTERM, stop); signal(SIGINT, stop);
    if (!frames) {
        pthread_t writer; atomic_store(&writing, 1);
        require(pthread_create(&writer, NULL, journal, NULL) == 0, "start journal writer");
        uint64_t started = now();
        while (now() - started < seconds * 1000000000ULL && !interrupted) {
            struct timespec delay = {0, 100000000}; nanosleep(&delay, NULL);
        }
        atomic_store(&writing, 0); require(pthread_join(writer, NULL) == 0, "join journal writer");
        require(close(directory) == 0 && !interrupted, "diagnostic interrupted");
        printf("{\"financial_operations\":0,\"baseline\":true,\"elapsed_ns\":%llu,",
               (unsigned long long)(now() - started));
        statistics("journal", journal_samples, journals); printf("}\n");
        return 0;
    }
    char path[220]; snprintf(path, sizeof(path), "%s/scratch.sqlite", argv[1]);
    sqlite3 *db = NULL;
    require(sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK,
            "open scratch database");
    sql(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;"
            "PRAGMA temp_store=memory; PRAGMA mmap_size=5242880;");
    char pragma[64]; snprintf(pragma, sizeof(pragma), "PRAGMA wal_autocheckpoint=%lu", frames);
    sql(db, pragma);
    sql(db, "CREATE TABLE scratch (id INTEGER PRIMARY KEY, data BLOB NOT NULL)");
    sqlite3_stmt *statement = NULL;
    require(sqlite3_prepare_v2(db, "INSERT INTO scratch VALUES (?1,?2)", -1, &statement, NULL)
            == SQLITE_OK, "prepare inserts");
    uint64_t setup = now();
    sql(db, "BEGIN IMMEDIATE"); rows(db, statement, 0, ROWS, 0); sql(db, "COMMIT");
    require(sqlite3_finalize(statement) == SQLITE_OK, "finish inserts");
    require(sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL) == SQLITE_OK,
            "initial checkpoint");
    setup = now() - setup;
    require(sqlite3_prepare_v2(db, "UPDATE scratch SET data=?2 WHERE id=?1", -1, &statement, NULL)
            == SQLITE_OK, "prepare updates");
    pthread_t writer; atomic_store(&writing, 1);
    require(pthread_create(&writer, NULL, journal, NULL) == 0, "start journal writer");
    uint64_t started = now(), updated = 0;
    for (unsigned cycle = 1; cycle <= 32 && now() - started < seconds * 1000000000ULL
         && !interrupted; cycle++) {
        for (unsigned first = 0; first < ROWS && now() - started < seconds * 1000000000ULL
             && !interrupted; first += BATCH) {
            unsigned last = first + BATCH < ROWS ? first + BATCH : ROWS;
            sql(db, "BEGIN IMMEDIATE"); rows(db, statement, first, last, cycle);
            uint64_t before = now(); sql(db, "COMMIT");
            require(commits < SAMPLE_CAP, "commit sample limit");
            commit_samples[commits++] = now() - before; updated += last - first;
        }
    }
    require(sqlite3_finalize(statement) == SQLITE_OK && sqlite3_close(db) == SQLITE_OK, "close database");
    atomic_store(&writing, 0); require(pthread_join(writer, NULL) == 0, "join journal writer");
    require(close(directory) == 0 && !interrupted, "diagnostic interrupted");
    printf("{\"financial_operations\":0,\"sqlite_version\":\"%s\",\"wal_frames\":%lu,"
           "\"rows\":%u,\"updated_rows\":%llu,\"setup_ns\":%llu,\"elapsed_ns\":%llu,",
           sqlite3_libversion(), frames, ROWS, (unsigned long long)updated,
           (unsigned long long)setup, (unsigned long long)(now() - started));
    statistics("journal", journal_samples, journals); printf(",");
    statistics("commit", commit_samples, commits); printf("}\n");
    return 0;
}
