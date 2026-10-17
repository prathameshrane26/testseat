#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>
#include "mongoose.h"
#include "optimizer.h"

static PGconn *conn = NULL;

#define JSON_HDR "Content-Type: application/json\r\n"

/* Built-in core admin (used when ADMIN_USER / ADMIN_PASSWORD env vars are not set).
   Change these values before deploying publicly. */
#define CORE_ADMIN_USER  "admin"
#define CORE_ADMIN_PASS  "Gala@Admin#2026"
#define CORE_ADMIN_EMAIL "admin@gala.com"

/* ---------- database ---------- */

// Returns 1 if the connection is usable (reconnects if it dropped)
static int ensure_db(void) {
    if (!conn) return 0;
    if (PQstatus(conn) != CONNECTION_OK) PQreset(conn);
    return PQstatus(conn) == CONNECTION_OK;
}

static void init_db(void) {
    const char *conninfo = getenv("DATABASE_URL");
    if (!conninfo) {
        fprintf(stderr, "DATABASE_URL is not set. Set it in your Render environment.\n");
        exit(1);
    }

    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection to NeonDB failed: %s\n", PQerrorMessage(conn));
        return;
    }
    printf("Connected to NeonDB (PostgreSQL) successfully.\n");

    const char *sql =
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
        "CREATE TABLE IF NOT EXISTS users ("
        "id SERIAL PRIMARY KEY,"
        "username TEXT UNIQUE NOT NULL,"
        "email TEXT UNIQUE NOT NULL,"
        "password TEXT NOT NULL,"
        "is_admin INTEGER DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS events ("
        "id SERIAL PRIMARY KEY,"
        "user_id INTEGER,"
        "event_name TEXT,"
        "event_data TEXT,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
        "CREATE UNIQUE INDEX IF NOT EXISTS events_user_uidx ON events(user_id);"
        "CREATE TABLE IF NOT EXISTS sessions ("
        "token TEXT PRIMARY KEY,"
        "user_id INTEGER NOT NULL,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);";

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        fprintf(stderr, "SQL error in table creation: %s\n", PQerrorMessage(conn));
    PQclear(res);

    // Core admin account: created / re-synced on every start.
    // Env vars ADMIN_USER / ADMIN_PASSWORD / ADMIN_EMAIL override the built-in defaults.
    const char *au = getenv("ADMIN_USER");
    const char *ap = getenv("ADMIN_PASSWORD");
    const char *ae = getenv("ADMIN_EMAIL");
    if (!au || !*au) au = CORE_ADMIN_USER;
    if (!ap || !*ap) ap = CORE_ADMIN_PASS;
    if (!ae || !*ae) ae = CORE_ADMIN_EMAIL;

    const char *vals[3] = { au, ae, ap };
    res = PQexecParams(conn,
        "INSERT INTO users (username, email, password, is_admin) "
        "VALUES ($1, $2, crypt($3, gen_salt('bf')), 1) "
        "ON CONFLICT (username) DO UPDATE "
        "SET password = crypt($3, gen_salt('bf')), is_admin = 1;",
        3, NULL, vals, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        fprintf(stderr, "Admin seed failed: %s\n", PQerrorMessage(conn));
    else
        printf("Core admin account '%s' ready.\n", au);
    PQclear(res);

    // Safety: only the core admin may hold admin rights
    const char *keep[1] = { au };
    res = PQexecParams(conn,
        "UPDATE users SET is_admin = 0 WHERE username <> $1 AND is_admin <> 0;",
        1, NULL, keep, NULL, NULL, 0);
    PQclear(res);
}

/* ---------- helpers ---------- */

// Minimal JSON string-field extractor (handles \" and \\ escapes)
static void extract_json_field(struct mg_str body, const char *key, char *dest, size_t dest_size) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    char *temp = (char *)malloc(body.len + 1);
    if (!temp) return;
    memcpy(temp, body.buf, body.len);
    temp[body.len] = '\0';

    char *p = strstr(temp, pattern);
    if (p) {
        p = strchr(p + strlen(pattern), ':');
        if (p) {
            p++;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            if (*p == '"') {
                p++;
                size_t i = 0;
                while (*p && *p != '"' && i < dest_size - 1) {
                    if (*p == '\\' && p[1]) p++;
                    dest[i++] = *p++;
                }
                dest[i] = '\0';
            }
        }
    }
    free(temp);
}

// Random 32-hex-char session token
static int make_token(char *out, size_t out_size) {
    unsigned char rnd[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t n = fread(rnd, 1, sizeof(rnd), f);
    fclose(f);
    if (n != sizeof(rnd) || out_size < 33) return 0;
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", rnd[i]);
    return 1;
}

// Validates "Authorization: Bearer <token>" against the sessions table
static int authenticate(struct mg_http_message *hm, int *user_id, int *is_admin) {
    struct mg_str *h = mg_http_get_header(hm, "Authorization");
    if (!h || h->len <= 7 || strncmp(h->buf, "Bearer ", 7) != 0) return 0;

    char token[80];
    size_t n = h->len - 7;
    if (n >= sizeof(token)) return 0;
    memcpy(token, h->buf + 7, n);
    token[n] = '\0';

    const char *vals[1] = { token };
    PGresult *res = PQexecParams(conn,
        "SELECT u.id, u.is_admin FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1;",
        1, NULL, vals, NULL, NULL, 0);
    int ok = 0;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        *user_id = atoi(PQgetvalue(res, 0, 0));
        *is_admin = atoi(PQgetvalue(res, 0, 1));
        ok = 1;
    }
    PQclear(res);
    return ok;
}

/* ---------- handlers ---------- */

static void handle_register(struct mg_connection *c, struct mg_http_message *hm) {
    char username[64] = {0}, email[128] = {0}, password[128] = {0};

    extract_json_field(hm->body, "username", username, sizeof(username));
    extract_json_field(hm->body, "email", email, sizeof(email));
    extract_json_field(hm->body, "password", password, sizeof(password));

    if (!*username || !*email || !*password) {
        mg_http_reply(c, 400, JSON_HDR, "{\"error\":\"Missing required fields (username, email, password)\"}\n");
        return;
    }
    if (strlen(password) < 6) {
        mg_http_reply(c, 400, JSON_HDR, "{\"error\":\"Password must be at least 6 characters\"}\n");
        return;
    }

    const char *vals[3] = { username, email, password };
    PGresult *res = PQexecParams(conn,
        "INSERT INTO users (username, email, password, is_admin) "
        "VALUES ($1, $2, crypt($3, gen_salt('bf')), 0);",
        3, NULL, vals, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        mg_http_reply(c, 400, JSON_HDR, "{\"error\":\"Username or email already exists\"}\n");
    else
        mg_http_reply(c, 201, JSON_HDR, "{\"message\":\"User registered successfully\"}\n");
    PQclear(res);
}

static void handle_login(struct mg_connection *c, struct mg_http_message *hm) {
    char username[64] = {0}, password[128] = {0};

    extract_json_field(hm->body, "username", username, sizeof(username));
    extract_json_field(hm->body, "password", password, sizeof(password));

    if (!*username || !*password) {
        mg_http_reply(c, 400, JSON_HDR, "{\"error\":\"Missing username or password\"}\n");
        return;
    }

    const char *vals[2] = { username, password };
    PGresult *res = PQexecParams(conn,
        "SELECT id, username, is_admin FROM users "
        "WHERE lower(username) = lower($1) AND password = crypt($2, password);",
        2, NULL, vals, NULL, NULL, 0);

    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        char id_str[16];
        snprintf(id_str, sizeof(id_str), "%s", PQgetvalue(res, 0, 0));
        int id = atoi(id_str);
        char uname[64];
        snprintf(uname, sizeof(uname), "%s", PQgetvalue(res, 0, 1));
        int is_admin = atoi(PQgetvalue(res, 0, 2));
        PQclear(res);

        char token[40];
        if (!make_token(token, sizeof(token))) {
            mg_http_reply(c, 500, JSON_HDR, "{\"error\":\"Could not create session\"}\n");
            return;
        }
        const char *sv[2] = { token, id_str };
        PGresult *sres = PQexecParams(conn,
            "INSERT INTO sessions (token, user_id) VALUES ($1, $2::int);",
            2, NULL, sv, NULL, NULL, 0);
        int ok = PQresultStatus(sres) == PGRES_COMMAND_OK;
        PQclear(sres);
        if (!ok) {
            mg_http_reply(c, 500, JSON_HDR, "{\"error\":\"Could not create session\"}\n");
            return;
        }

        mg_http_reply(c, 200, JSON_HDR,
                      "{\"message\":\"Login successful\",\"id\":%d,\"token\":%m,\"username\":%m,\"isAdmin\":%s}\n",
                      id, MG_ESC(token), MG_ESC(uname), is_admin ? "true" : "false");
        return;
    }

    PQclear(res);
    mg_http_reply(c, 401, JSON_HDR, "{\"error\":\"Invalid username or password\"}\n");
}

// Saves (upserts) the logged-in user's seating plan
static void handle_save_event(struct mg_connection *c, struct mg_http_message *hm) {
    int uid = 0, adm = 0;
    if (!authenticate(hm, &uid, &adm)) {
        mg_http_reply(c, 401, JSON_HDR, "{\"error\":\"Not authenticated\"}\n");
        return;
    }

    char *body_str = (char *)malloc(hm->body.len + 1);
    if (!body_str) {
        mg_http_reply(c, 500, JSON_HDR, "{\"error\":\"Memory allocation error\"}\n");
        return;
    }
    memcpy(body_str, hm->body.buf, hm->body.len);
    body_str[hm->body.len] = '\0';

    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", uid);
    const char *vals[2] = { uid_str, body_str };

    // $2::json rejects malformed JSON so the load endpoint can never return broken data
    PGresult *res = PQexecParams(conn,
        "INSERT INTO events (user_id, event_name, event_data) "
        "VALUES ($1::int, 'Seating Plan', $2::json::text) "
        "ON CONFLICT (user_id) DO UPDATE "
        "SET event_data = EXCLUDED.event_data, created_at = CURRENT_TIMESTAMP;",
        2, NULL, vals, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        mg_http_reply(c, 400, JSON_HDR, "{\"error\":\"Failed to save event\"}\n");
    else
        mg_http_reply(c, 200, JSON_HDR, "{\"message\":\"Event seating saved successfully\"}\n");

    PQclear(res);
    free(body_str);
}

// Loads the logged-in user's seating plan
static void handle_load_event(struct mg_connection *c, struct mg_http_message *hm) {
    int uid = 0, adm = 0;
    if (!authenticate(hm, &uid, &adm)) {
        mg_http_reply(c, 401, JSON_HDR, "{\"error\":\"Not authenticated\"}\n");
        return;
    }

    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", uid);
    const char *vals[1] = { uid_str };
    PGresult *res = PQexecParams(conn,
        "SELECT event_data FROM events WHERE user_id = $1::int ORDER BY id DESC LIMIT 1;",
        1, NULL, vals, NULL, NULL, 0);

    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
        mg_http_reply(c, 200, JSON_HDR, "{\"eventData\":%s}\n", PQgetvalue(res, 0, 0));
    else
        mg_http_reply(c, 200, JSON_HDR, "{\"eventData\":null}\n");

    PQclear(res);
}

// Admin only: all accounts with their latest saved plan
static void handle_admin_users(struct mg_connection *c, struct mg_http_message *hm) {
    int uid = 0, adm = 0;
    if (!authenticate(hm, &uid, &adm)) {
        mg_http_reply(c, 401, JSON_HDR, "{\"error\":\"Not authenticated\"}\n");
        return;
    }
    if (!adm) {
        mg_http_reply(c, 403, JSON_HDR, "{\"error\":\"Admin access required\"}\n");
        return;
    }

    PGresult *res = PQexec(conn,
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
        "  SELECT u.id, u.username, u.email, u.is_admin,"
        "    (SELECT count(*) FROM events e WHERE e.user_id = u.id) AS total_events,"
        "    (SELECT e.event_data::json FROM events e WHERE e.user_id = u.id ORDER BY e.id DESC LIMIT 1) AS \"eventData\""
        "  FROM users u ORDER BY u.id"
        ") t;");

    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
        mg_http_reply(c, 200, JSON_HDR, "%s", PQgetvalue(res, 0, 0));
    else
        mg_http_reply(c, 500, JSON_HDR, "{\"error\":\"Failed to load users\"}\n");

    PQclear(res);
}

/* ---------- router ---------- */

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    if (mg_match(hm->uri, mg_str("/api/#"), NULL)) {
        if (!ensure_db()) {
            mg_http_reply(c, 503, JSON_HDR, "{\"error\":\"Database unavailable\"}\n");
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/auth/register"), NULL))      handle_register(c, hm);
        else if (mg_match(hm->uri, mg_str("/api/auth/login"), NULL))    handle_login(c, hm);
        else if (mg_match(hm->uri, mg_str("/api/admin/users"), NULL))   handle_admin_users(c, hm);
        else if (mg_match(hm->uri, mg_str("/api/events/save"), NULL))   handle_save_event(c, hm);
        else if (mg_match(hm->uri, mg_str("/api/events/load"), NULL))   handle_load_event(c, hm);
        else mg_http_reply(c, 404, JSON_HDR, "{\"error\":\"Not found\"}\n");
        return;
    }

    struct mg_http_serve_opts opts = { .root_dir = "frontend" };
    mg_http_serve_dir(c, hm, &opts);
}

int main(void) {
    init_db();

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);

    int port = 5000;
    char *env_port = getenv("PORT");
    if (env_port) port = atoi(env_port);

    char s_url[64];
    snprintf(s_url, sizeof(s_url), "http://0.0.0.0:%d", port);
    printf("Starting C backend with NeonDB on %s\n", s_url);

    if (mg_http_listen(&mgr, s_url, fn, NULL) == NULL) {
        fprintf(stderr, "Error starting server on %s\n", s_url);
        return 1;
    }

    for (;;) mg_mgr_poll(&mgr, 1000);

    PQfinish(conn);
    mg_mgr_free(&mgr);
    return 0;
}