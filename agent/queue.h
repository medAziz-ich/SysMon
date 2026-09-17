#ifndef QUEUE_H
#define QUEUE_H

#include <sqlite3.h>
#include <pthread.h>

extern pthread_mutex_t queue_mutex;

int queue_init(const char *db_path);
int queue_enqueue(const char *payload);
char *queue_dequeue(sqlite3_int64 *out_id, int *retry_count, time_t *first_attempt);  // Modifié pour renvoyer retry et first_attempt
int queue_update_retry(sqlite3_int64 id, int new_retry);
int queue_delete(sqlite3_int64 id);
void queue_close();

#endif
