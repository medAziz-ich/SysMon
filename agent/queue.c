#include "queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static sqlite3 *db = NULL;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Declared in main.c — used to wake the sender thread after enqueue */
extern pthread_cond_t queue_cond;

int queue_init(const char *db_path) {
    pthread_mutex_lock(&queue_mutex);
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open queue database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        pthread_mutex_unlock(&queue_mutex);
        return -1;
    }

    const char *create_sql =
        "CREATE TABLE IF NOT EXISTS pending_messages ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  payload       TEXT NOT NULL,"
        "  retry_count   INTEGER DEFAULT 0,"
        "  first_attempt INTEGER,"
        "  created_at    INTEGER DEFAULT (strftime('%s','now'))"
        ");";

    char *err = NULL;
    rc = sqlite3_exec(db, create_sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating table: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        pthread_mutex_unlock(&queue_mutex);
        return -1;
    }
    pthread_mutex_unlock(&queue_mutex);
    printf("SQLite persistent queue initialized: %s\n", db_path);

    /* Enable WAL mode: much better for concurrent reads/writes */
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    return 0;
}

int queue_enqueue(const char *payload) {
    pthread_mutex_lock(&queue_mutex);
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO pending_messages (payload, first_attempt) VALUES (?, ?);";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&queue_mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, payload, -1, SQLITE_TRANSIENT);  // Copie pour éviter problèmes avec free immédiat
    sqlite3_bind_int64(stmt, 2, time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&queue_mutex);

    if (rc == SQLITE_DONE) {
        /* Wake up sender_thread so it doesn't wait unnecessarily */
        pthread_mutex_lock(&queue_mutex);
        pthread_cond_signal(&queue_cond);
        pthread_mutex_unlock(&queue_mutex);
    }

    return (rc == SQLITE_DONE) ? 0 : -1;
}

char *queue_dequeue(sqlite3_int64 *out_id, int *retry_count, time_t *first_attempt) {
    pthread_mutex_lock(&queue_mutex);
    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, payload, retry_count, first_attempt FROM pending_messages ORDER BY id ASC LIMIT 1;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&queue_mutex);
        return NULL;
    }

    char *result = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
    *out_id           = sqlite3_column_int64(stmt, 0);
    const char *payload = (const char *)sqlite3_column_text(stmt, 1);
    *retry_count      = sqlite3_column_int(stmt, 2);
    *first_attempt    = (time_t)sqlite3_column_int64(stmt, 3);
    result = strdup(payload);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&queue_mutex);
    return result;
}

int queue_update_retry(sqlite3_int64 id, int new_retry) {
    pthread_mutex_lock(&queue_mutex);
    sqlite3_stmt *stmt;
    const char *sql = "UPDATE pending_messages SET retry_count = ? WHERE id = ?;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Prepare failed (update_retry): %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&queue_mutex);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, new_retry);
    sqlite3_bind_int64(stmt, 2, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Update failed: %s\n", sqlite3_errmsg(db));
    }
    pthread_mutex_unlock(&queue_mutex);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int queue_delete(sqlite3_int64 id) {
    pthread_mutex_lock(&queue_mutex);
    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM pending_messages WHERE id = ?;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Prepare failed (delete): %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&queue_mutex);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Delete failed: %s\n", sqlite3_errmsg(db));
    }
    pthread_mutex_unlock(&queue_mutex);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

void queue_close() {
    pthread_mutex_lock(&queue_mutex);
    if (db) sqlite3_close(db);
    pthread_mutex_unlock(&queue_mutex);
}
