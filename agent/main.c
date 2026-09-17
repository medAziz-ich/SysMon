#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <regex.h>
#include <sys/statvfs.h>
#include <curl/curl.h>
#include "cJSON.h"
#include "queue.h"


typedef struct StringList { char *str; struct StringList *next; } StringList;
typedef struct LogMonitor {
    char *name;
    char *file;
    regex_t regex;
    struct LogMonitor *next;
} LogMonitor;
typedef struct NetIface {
    char *name;
    unsigned long long prev_rx, prev_tx;
    time_t prev_time;
    double rx_bps, tx_bps;
    struct NetIface *next;
} NetIface;



volatile int running = 1;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

char *server_url        = NULL;
char *auth_token        = NULL;
char *register_url      = NULL;   /* derived: base_url + /register */
char *reg_secret        = NULL;   /* registration secret from config */
char *ca_cert_path      = NULL;   /* FIX #3 — path to server CA cert for SSL verification */
char *queue_db_path     = NULL;   /* path to SQLite queue DB — configurable */
int   interval          = 60;
int   max_buffer        = 1000;
char  hostname[256];

/* ── libcurl response buffer ── */
typedef struct { char *data; size_t size; } CurlBuf;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    CurlBuf *buf = userdata;
    size_t total = size * nmemb;
    buf->data = realloc(buf->data, buf->size + total + 1);
    memcpy(buf->data + buf->size, ptr, total);
    buf->size += total;
    buf->data[buf->size] = '\0';
    return total;
}

StringList *disk_paths = NULL;
StringList *services = NULL;
NetIface *net_ifaces = NULL;
LogMonitor *log_monitors = NULL;

// ------------------- Helpers -------------------
void add_stringlist(StringList **list, const char *s) {
    StringList *n = malloc(sizeof(StringList));
    n->str = strdup(s);
    n->next = *list;
    *list = n;
}

void add_netiface(const char *name) {
    NetIface *n = calloc(1, sizeof(NetIface));
    n->name = strdup(name);
    n->prev_time = time(NULL);
    n->next = net_ifaces;
    net_ifaces = n;
}

void add_logmonitor(const char *name, const char *file, const char *regex_str) {
    LogMonitor *n = calloc(1, sizeof(LogMonitor));
    n->name = strdup(name);
    n->file = strdup(file);
    regcomp(&n->regex, regex_str, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    n->next = log_monitors;
    log_monitors = n;
}

// ── FIX #8 Memory cleanup ─────────────────────────────────────────────────────
static void free_stringlist(StringList *list) {
    while (list) {
        StringList *next = list->next;
        free(list->str);
        free(list);
        list = next;
    }
}

static void free_netifaces(NetIface *list) {
    while (list) {
        NetIface *next = list->next;
        free(list->name);
        free(list);
        list = next;
    }
}

static void free_logmonitors(LogMonitor *list) {
    while (list) {
        LogMonitor *next = list->next;
        free(list->name);
        free(list->file);
        regfree(&list->regex);
        free(list);
        list = next;
    }
}

static void cleanup_globals(void) {
    free_stringlist(disk_paths);    disk_paths   = NULL;
    free_stringlist(services);      services     = NULL;
    free_netifaces(net_ifaces);     net_ifaces   = NULL;
    free_logmonitors(log_monitors); log_monitors = NULL;
    free(server_url);    server_url    = NULL;
    free(auth_token);    auth_token    = NULL;
    free(register_url);  register_url  = NULL;
    free(reg_secret);    reg_secret    = NULL;
    free(ca_cert_path);  ca_cert_path  = NULL;
    free(queue_db_path); queue_db_path = NULL;
}

// ------------------- Config -------------------
void load_config(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open config file: %s\n", path);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (fread(data, 1, len, f) != (size_t)len) {
        fprintf(stderr, "Warning: partial read of config file\n"); }
    fclose(f);
    data[len] = '\0';

    cJSON *json = cJSON_Parse(data);
    free(data);

    if (!json) {
        fprintf(stderr, "Failed to parse config JSON: %s\n", path);
        exit(1);
    }

    cJSON *j_url   = cJSON_GetObjectItem(json, "server_url");
    cJSON *j_token = cJSON_GetObjectItem(json, "auth_token");
    cJSON *j_reg   = cJSON_GetObjectItem(json, "registration_secret");

    if (!j_url) {
        fprintf(stderr, "Config missing required field: server_url\n");
        cJSON_Delete(json);
        exit(1);
    }
    server_url = strdup(j_url->valuestring);

    /* auth_token is optional — may be absent on first run (agent will register) */
    if (j_token && strlen(j_token->valuestring) > 0)
        auth_token = strdup(j_token->valuestring);

    /* registration_secret is needed only if auth_token is absent */
    if (j_reg)
        reg_secret = strdup(j_reg->valuestring);

    /* FIX #3 — load optional CA cert path for SSL peer verification */
    cJSON *j_ca = cJSON_GetObjectItem(json, "ca_cert");
    if (j_ca && j_ca->valuestring && strlen(j_ca->valuestring) > 0)
        ca_cert_path = strdup(j_ca->valuestring);

    /* Load optional queue DB path — defaults to /var/lib/sysmon-agent/queue.db */
    cJSON *j_qdb = cJSON_GetObjectItem(json, "queue_db");
    if (j_qdb && j_qdb->valuestring && strlen(j_qdb->valuestring) > 0)
        queue_db_path = strdup(j_qdb->valuestring);
    else
        queue_db_path = strdup("/var/lib/sysmon-agent/queue.db");

    /* Build register URL: replace /ingest suffix with /register, or append /register */
    {
        char *base = strdup(server_url);
        char *ingest = strstr(base, "/ingest");
        if (ingest) *ingest = '\0';
        size_t rlen = strlen(base) + 12;
        register_url = malloc(rlen);
        snprintf(register_url, rlen, "%s/register", base);  /* FIX #9 — bounded */
        free(base);
    }
    if (cJSON_GetObjectItem(json, "interval_seconds"))
        interval = cJSON_GetObjectItem(json, "interval_seconds")->valueint;
    if (cJSON_GetObjectItem(json, "max_buffer"))
        max_buffer = cJSON_GetObjectItem(json, "max_buffer")->valueint;

    gethostname(hostname, sizeof(hostname));

    // disks, interfaces, services, logs...
    cJSON *arr;
    if ((arr = cJSON_GetObjectItem(json, "disk_paths")))
        for (int i = 0; i < cJSON_GetArraySize(arr); i++)
            add_stringlist(&disk_paths, cJSON_GetArrayItem(arr, i)->valuestring);

    if ((arr = cJSON_GetObjectItem(json, "network_interfaces")))
        for (int i = 0; i < cJSON_GetArraySize(arr); i++)
            add_netiface(cJSON_GetArrayItem(arr, i)->valuestring);

    if ((arr = cJSON_GetObjectItem(json, "services")))
        for (int i = 0; i < cJSON_GetArraySize(arr); i++) {
            const char *svc = cJSON_GetArrayItem(arr, i)->valuestring;
            /* FIX #8 — validate service name before use in popen() shell command */
            int valid = 1;
            if (!svc || strlen(svc) == 0 || strlen(svc) >= 128) { valid = 0; }
            for (const char *p = svc; valid && *p; p++)
                if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.')
                    valid = 0;
            if (valid)
                add_stringlist(&services, svc);
            else
                fprintf(stderr, "Warning: skipping invalid service name '%s'\n", svc ? svc : "");
        }

    if ((arr = cJSON_GetObjectItem(json, "log_monitors"))) {
        for (int i = 0; i < cJSON_GetArraySize(arr); i++) {
            cJSON *item = cJSON_GetArrayItem(arr, i);
            add_logmonitor(
                cJSON_GetObjectItem(item, "name")->valuestring,
                cJSON_GetObjectItem(item, "file")->valuestring,
                cJSON_GetObjectItem(item, "regex")->valuestring
            );
        }
    }
    cJSON_Delete(json);
}

// ------------------- Metrics -------------------
double get_cpu_usage() {
    static unsigned long long prev_total = 0, prev_idle = 0;
    FILE *f = fopen("/proc/stat", "r");
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
           &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice) != 10)
        { fclose(f); return 0.0; }
    fclose(f);

    unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
    unsigned long long idl = idle + iowait;

    if (prev_total == 0) {
        prev_total = total; prev_idle = idl;
        return 0.0;
    }

    double usage = (double)(total - prev_total - (idl - prev_idle)) / (total - prev_total) * 100.0;
    prev_total = total; prev_idle = idl;
    return usage;
}

double get_ram_usage() {
    FILE *f = fopen("/proc/meminfo", "r");
    long total = 0, avail = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %ld", &total) == 1) continue;
        if (sscanf(line, "MemAvailable: %ld", &avail) == 1) break;
    }
    fclose(f);
    return total ? (double)(total - avail) / total * 100.0 : 0.0;
}

double get_disk_usage(const char *path) {
    struct statvfs vfs;
    if (statvfs(path, &vfs) != 0) return -1.0;
    unsigned long long total = (unsigned long long)vfs.f_blocks * vfs.f_frsize;
    unsigned long long free = (unsigned long long)vfs.f_bfree * vfs.f_frsize;
    return total ? (double)(total - free) / total * 100.0 : 0.0;
}

void update_network() {
    FILE *f = fopen("/proc/net/dev", "r");
    char line[512];
    { char *_r; _r = fgets(line, sizeof(line), f); _r = fgets(line, sizeof(line), f); (void)_r; } /* skip headers */

    while (fgets(line, sizeof(line), f)) {
        char iface[32];
        unsigned long long rx, tx;
        if (sscanf(line, "%31[^:]: %llu %*u %*u %*u %*u %*u %*u %*u %llu", iface, &rx, &tx) != 3) continue;
        char *colon = strchr(iface, ':'); if (colon) *colon = 0;

        for (NetIface *ni = net_ifaces; ni; ni = ni->next) {
            if (strcmp(ni->name, iface) == 0) {
                time_t now = time(NULL);
                double dt = difftime(now, ni->prev_time);
                if (dt > 0) {
                    ni->rx_bps = (rx - ni->prev_rx) / dt;
                    ni->tx_bps = (tx - ni->prev_tx) / dt;
                }
                ni->prev_rx = rx;
                ni->prev_tx = tx;
                ni->prev_time = now;
                break;
            }
        }
    }
    fclose(f);
}

char *get_service_status(const char *svc) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "systemctl show -p ActiveState --value %s 2>/dev/null", svc);
    FILE *p = popen(cmd, "r");
    char buf[64] = "unknown";
    { char *_r = fgets(buf, sizeof(buf), p); (void)_r; }
    pclose(p);
    buf[strcspn(buf, "\n")] = 0;
    return strdup(buf);
}

// ------------------- Queue & Sender -------------------

/* Returns HTTP status code (e.g. 202, 401, 0 on curl error) */
long send_payload(const char *payload) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct curl_slist *headers = NULL;
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", auth_token);
    headers = curl_slist_append(headers, auth);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, server_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    /* FIX #3 — verify server certificate when ca_cert is configured */
    if (ca_cert_path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO,        ca_cert_path);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        fprintf(stderr, "WARNING: ca_cert not set — SSL peer verification disabled.\n");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? code : 0;
}

/*
 * Auto-registration: called on startup when auth_token is missing.
 * Sends { "agent_name": hostname, "secret": reg_secret } to /register
 * and saves the returned api_key back into config.json.
 */
bool auto_register(const char *config_path) {
    if (!reg_secret) {
        fprintf(stderr, "No auth_token and no registration_secret in config — cannot register.\n");
        return false;
    }

    printf("No auth_token found — auto-registering with server...\n");

    /* Build JSON body */
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "agent_name", hostname);
    cJSON_AddStringToObject(body, "secret",     reg_secret);
    char *payload = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    /* POST to /register */
    CURL *curl = curl_easy_init();
    if (!curl) { free(payload); return false; }

    CurlBuf buf = { .data = malloc(1), .size = 0 };
    buf.data[0] = '\0';

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL,            register_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     payload);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        15L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,       1L);
    /* FIX #3 — verify server certificate when ca_cert is configured */
    if (ca_cert_path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO,        ca_cert_path);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        fprintf(stderr, "WARNING: ca_cert not set — SSL peer verification disabled.\n");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &buf);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(payload);

    if (res != CURLE_OK || code != 201) {
        fprintf(stderr, "Registration failed (HTTP %ld): %s\n", code, buf.data);
        free(buf.data);
        return false;
    }

    /* Parse returned api_key */
    cJSON *resp = cJSON_Parse(buf.data);
    free(buf.data);
    if (!resp) { fprintf(stderr, "Invalid registration response.\n"); return false; }

    cJSON *j_key = cJSON_GetObjectItem(resp, "api_key");
    if (!j_key) { fprintf(stderr, "No api_key in registration response.\n"); cJSON_Delete(resp); return false; }

    auth_token = strdup(j_key->valuestring);
    cJSON_Delete(resp);
    printf("✔ Registered! api_key received.\n");

    /* Save api_key back into config.json for next run */
    FILE *f = fopen(config_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *data = malloc(len + 1);
        if (fread(data, 1, len, f) != (size_t)len)
            fprintf(stderr, "Warning: partial config read\n");
        fclose(f);
        data[len] = '\0';

        cJSON *cfg = cJSON_Parse(data);
        free(data);
        if (cfg) {
            /* Update or insert auth_token */
            cJSON *existing = cJSON_GetObjectItem(cfg, "auth_token");
            if (existing)
                cJSON_SetValuestring(existing, auth_token);
            else
                cJSON_AddStringToObject(cfg, "auth_token", auth_token);

            char *updated = cJSON_Print(cfg);
            cJSON_Delete(cfg);

            f = fopen(config_path, "w");
            if (f) {
                fputs(updated, f);
                fclose(f);
                printf("✔ auth_token saved to %s\n", config_path);
            } else {
                fprintf(stderr, "Warning: could not write auth_token back to config.\n");
                fprintf(stderr, "Add manually: \"auth_token\": \"%s\"\n", auth_token);
            }
            free(updated);
        }
    }

    return true;
}

void *sender_thread(void *arg) {
    const char *config_path = (const char *)arg;

    const int BACKOFF_BASE_SEC = 5;
    const int BACKOFF_MAX_SEC  = 120;
    const int MAX_RETRIES      = 12;
    const int MAX_AGE_SECONDS  = 86400 * 7; // 7 days

    while (running) {
        sqlite3_int64 row_id = 0;
        int retry_count = 0;
        time_t first_attempt = 0;
        char *payload = queue_dequeue(&row_id, &retry_count, &first_attempt);

        if (!payload) {
            pthread_mutex_lock(&queue_mutex);
            pthread_cond_wait(&queue_cond, &queue_mutex);
            pthread_mutex_unlock(&queue_mutex);
            continue;
        }

        time_t now = time(NULL);
        if (now - first_attempt > MAX_AGE_SECONDS) {
            fprintf(stderr, "Dropped old payload (age > 7d)\n");
            queue_delete(row_id);
            free(payload);
            continue;
        }

        int backoff_sec = 0;
        if (retry_count > 0) {
            backoff_sec = BACKOFF_BASE_SEC;
            for (int i = 1; i < retry_count && backoff_sec < BACKOFF_MAX_SEC; i++)
                backoff_sec *= 2;
            if (backoff_sec > BACKOFF_MAX_SEC)
                backoff_sec = BACKOFF_MAX_SEC;
            sleep(backoff_sec);
        }

        long http_code = send_payload(payload);
        bool success   = (http_code >= 200 && http_code < 300);

        if (success) {
            queue_delete(row_id);
            free(payload);

        } else if (http_code == 401) {
            /* Token rejected — re-register automatically and retry immediately */
            fprintf(stderr, "Got 401 — token rejected. Re-registering with server...\n");
            free(auth_token);
            auth_token = NULL;

            if (auto_register(config_path)) {
                fprintf(stderr, "Re-registration successful — retrying payload.\n");
                /* Reset retry counter so this payload gets a fresh chance */
                queue_update_retry(row_id, 0);
            } else {
                fprintf(stderr, "Re-registration failed — will retry later.\n");
                queue_update_retry(row_id, retry_count + 1);
            }
            free(payload);
            usleep(400000);

        } else if (http_code == 429) {
            /* Rate limited — server told us to back off */
            fprintf(stderr, "Rate limited (429) — backing off 60s before retry.\n");
            queue_update_retry(row_id, retry_count); /* don't increment — not a real failure */
            free(payload);
            sleep(60);

        } else {
            retry_count++;
            if (retry_count >= MAX_RETRIES) {
                fprintf(stderr, "Dropped payload after %d failed attempts (id=%lld)\n",
                        retry_count, row_id);
                queue_delete(row_id);
                free(payload);
            } else {
                if (queue_update_retry(row_id, retry_count) != 0)
                    fprintf(stderr, "Failed to update retry_count for id=%lld\n", row_id);
                int next_delay = backoff_sec ? backoff_sec : BACKOFF_BASE_SEC;
                fprintf(stderr, "Send failed (attempt %d/%d) id=%lld -> next retry in ~%d s\n",
                        retry_count, MAX_RETRIES, row_id, next_delay);
                free(payload);
            }
            usleep(400000);
        }
    }
    return NULL;
}

// ------------------- Collector -------------------
void *collector_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(interval);

        update_network();

        cJSON *root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "timestamp", time(NULL));
        cJSON_AddStringToObject(root, "hostname", hostname);
        cJSON_AddNumberToObject(root, "cpu_percent", get_cpu_usage());
        cJSON_AddNumberToObject(root, "ram_percent", get_ram_usage());

        // disks
        cJSON *darr = cJSON_CreateArray();
        for (StringList *d = disk_paths; d; d = d->next) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "path", d->str);
            cJSON_AddNumberToObject(obj, "percent", get_disk_usage(d->str));
            cJSON_AddItemToArray(darr, obj);
        }
        cJSON_AddItemToObject(root, "disks", darr);

        // network
        cJSON *narr = cJSON_CreateArray();
        for (NetIface *ni = net_ifaces; ni; ni = ni->next) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "interface", ni->name);
            cJSON_AddNumberToObject(obj, "rx_bps", ni->rx_bps);
            cJSON_AddNumberToObject(obj, "tx_bps", ni->tx_bps);
            cJSON_AddItemToArray(narr, obj);
        }
        cJSON_AddItemToObject(root, "network", narr);

        // services
        cJSON *sarr = cJSON_CreateArray();
        for (StringList *s = services; s; s = s->next) {
            char *st = get_service_status(s->str);
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "name", s->str);
            cJSON_AddStringToObject(obj, "status", st);
            cJSON_AddItemToArray(sarr, obj);
            free(st);
        }
        cJSON_AddItemToObject(root, "services", sarr);

        char *json = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        queue_enqueue(json);
        free(json);
    }
    return NULL;
}

// ------------------- Log Tailer -------------------
void *log_tailer(void *arg) {
    LogMonitor *lm = arg;
    FILE *f = fopen(lm->file, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);

    char line[8192];
    while (running) {
        if (fgets(line, sizeof(line), f)) {
            if (regexec(&lm->regex, line, 0, NULL, 0) == 0) {
                cJSON *root = cJSON_CreateObject();
                cJSON_AddNumberToObject(root, "timestamp", time(NULL));
                cJSON_AddStringToObject(root, "hostname", hostname);
                cJSON_AddStringToObject(root, "type", "log_event");
                cJSON_AddStringToObject(root, "source", lm->name);
                line[strcspn(line, "\n")] = 0;
                cJSON_AddStringToObject(root, "message", line);

                char *json = cJSON_PrintUnformatted(root);
                cJSON_Delete(root);
                queue_enqueue(json);
                free(json);
            }
        } else {
            clearerr(f);
            sleep(1);
        }
    }
    fclose(f);
    return NULL;
}

// ------------------- Main -------------------
void sig_handler(int sig) { (void)sig; running = 0; }

int main(int argc, char **argv) {
    const char *config_path = argc > 1 ? argv[1] : "/etc/sysmon-agent/config.json";

    load_config(config_path);

    /* Auto-register if no auth_token present */
    if (!auth_token || strlen(auth_token) == 0) {
        curl_global_init(CURL_GLOBAL_ALL);
        if (!auto_register(config_path)) {
            fprintf(stderr, "Could not obtain an API key. Exiting.\n");
            return 1;
        }
    } else {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    if (!server_url) {
        fprintf(stderr, "Missing server_url\n");
        return 1;
    }
  // Initialize persistent queue
  if (queue_init(queue_db_path) != 0)  {
    fprintf(stderr, "Failed to initialize SQLite queue\n");
    return 1;
  }


    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Start log tailers
    int num_logs = 0;
    for (LogMonitor *l = log_monitors; l; l = l->next) num_logs++;
    pthread_t *log_tids = num_logs ? malloc(num_logs * sizeof(pthread_t)) : NULL;
    int i = 0;
    for (LogMonitor *l = log_monitors; l; l = l->next)
        pthread_create(&log_tids[i++], NULL, log_tailer, l);

    // Collector + Sender
    pthread_t coll_tid, send_tid;
    pthread_create(&coll_tid, NULL, collector_thread, NULL);
    pthread_create(&send_tid, NULL, sender_thread, (void *)config_path);

    printf("sysmon-agent started (config: %s)\n", config_path);

    while (running) sleep(1);

    // Cleanup
    pthread_join(coll_tid, NULL);
    pthread_join(send_tid, NULL);
    for (int j = 0; j < num_logs; j++) pthread_join(log_tids[j], NULL);
    free(log_tids);
    queue_close();
    curl_global_cleanup();
    cleanup_globals();    /* FIX #8 — free all heap-allocated config data */
    printf("sysmon-agent stopped cleanly.\n");
    return 0;
}
