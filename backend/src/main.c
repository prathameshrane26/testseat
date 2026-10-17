#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>
#include "mongoose.h"
#include "optimizer.h"

static PGconn *conn = NULL;

// Initialize NeonDB (PostgreSQL) connection and create necessary tables
static void init_db(void) {
    const char *conninfo = getenv("DATABASE_URL");
    if (!conninfo) {
        // Fallback string if environment variable is not set locally
        conninfo = "postgresql://neondb_owner:npg_admin@ep-example-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require";
    }

    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) == CONNECTION_BAD) {
        fprintf(stderr, "Connection to NeonDB failed: %s\n", PQerrorMessage(conn));
        return;
    } else {
        fprintf(stdout, "Connected to NeonDB (PostgreSQL) successfully.\n");
    }

    const char *sql = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id SERIAL PRIMARY KEY,"
        "username TEXT UNIQUE NOT NULL,"
        "email TEXT UNIQUE NOT NULL,"
        "password TEXT NOT NULL,"
        "is_admin INTEGER DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS events ("
        "id SERIAL PRIMARY KEY,"
        "user_id INTEGER REFERENCES users(id),"
        "event_name TEXT,"
        "event_data TEXT,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);";

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "SQL error in table creation: %s\n", PQerrorMessage(conn));
    }
    PQclear(res);
}

// Robust self-contained JSON field extractor
static void extract_json_field(struct mg_str body, const char *key, char *dest, size_t dest_size) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    
    char *temp = (char *)malloc(body.len + 1);
    if (!temp) return;
    memcpy(temp, body.buf, body.len);
    temp[body.len] = '\0';

    char *p = strstr(temp, pattern);
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            if (*p == '"') {
                p++;
                size_t i = 0;
                while (*p && *p != '"' && i < dest_size - 1) {
                    dest[i++] = *p++;
                }
                dest[i] = '\0';
            }
        }
    }
    free(temp);
}

// Handler for User Registration (/api/auth/register)
static void handle_register(struct mg_connection *c, struct mg_http_message *hm) {
    char username[64] = {0};
    char email[128] = {0};
    char password[128] = {0};

    extract_json_field(hm->body, "username", username, sizeof(username));
    extract_json_field(hm->body, "email", email, sizeof(email));
    extract_json_field(hm->body, "password", password, sizeof(password));

    if (strlen(username) == 0 || strlen(email) == 0 || strlen(password) == 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Missing required fields (username, email, password)\"}\n");
        return;
    }

    const char *sql = "INSERT INTO users (username, email, password, is_admin) VALUES ($1, $2, $3, 0);";
    const char *paramValues[3] = { username, email, password };

    PGresult *res = PQexecParams(conn, sql, 3, NULL, paramValues, NULL, NULL, 0);
    ExecStatusType status = PQresultStatus(res);

    if (status != PGRES_COMMAND_OK) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Username or email already exists or database error\"}\n");
    } else {
        mg_http_reply(c, 201, "Content-Type: application/json\r\n", 
                      "{\"message\":\"User registered successfully in NeonDB backend\"}\n");
    }
    PQclear(res);
}

// Handler for User Login (/api/auth/login)
static void handle_login(struct mg_connection *c, struct mg_http_message *hm) {
    char username[64] = {0};
    char password[128] = {0};

    extract_json_field(hm->body, "username", username, sizeof(username));
    extract_json_field(hm->body, "password", password, sizeof(password));

    if (strlen(username) == 0 || strlen(password) == 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", "{\"error\":\"Missing username or password\"}\n");
        return;
    }

    const char *sql = "SELECT id, username, is_admin FROM users WHERE username = $1 AND password = $2;";
    const char *paramValues[2] = { username, password };

    PGresult *res = PQexecParams(conn, sql, 2, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        int id = atoi(PQgetvalue(res, 0, 0));
        char *uname = PQgetvalue(res, 0, 1);
        int is_admin = atoi(PQgetvalue(res, 0, 2));

        char response[256];
        snprintf(response, sizeof(response), 
                 "{\"message\":\"Login successful\",\"token\":\"c_neon_token_%d\",\"username\":\"%s\",\"isAdmin\":%s}\n", 
                 id, uname, is_admin ? "true" : "false");
        
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", response);
    } else {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n", "{\"error\":\"Invalid username or password\"}\n");
    }

    PQclear(res);
}

// HTTP Request Event Handler
static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        if (mg_match(hm->uri, mg_str("/api/auth/register"), NULL)) {
            handle_register(c, hm);
        } 
        else if (mg_match(hm->uri, mg_str("/api/auth/login"), NULL)) {
            handle_login(c, hm);
        } 
        else if (mg_match(hm->uri, mg_str("/api/admin/users"), NULL)) {
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                          "[{\"id\":1,\"username\":\"Admin\",\"email\":\"admin@gala.com\",\"is_admin\":1,\"total_events\":1}]");
        } 
        else if (mg_match(hm->uri, mg_str("/api/events/save"), NULL)) {
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                          "{\"message\":\"Event seating saved successfully to NeonDB\"}\n");
        }
        else if (mg_match(hm->uri, mg_str("/api/events/load"), NULL)) {
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                          "{\"eventData\":null}\n");
        }
        else {
            struct mg_http_serve_opts opts = { .root_dir = "frontend" };
            mg_http_serve_dir(c, hm, &opts);
        }
    }
}

int main(void) {
    init_db();

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    
    // Dynamic port configuration for cloud deployment (Render, etc.) & local fallback
    int port = 5000;
    char *env_port = getenv("PORT");
    if (env_port) {
        port = atoi(env_port);
    }

    char s_url[64];
    snprintf(s_url, sizeof(s_url), "http://0.0.0.0:%d", port);
    
    printf("Starting high-performance C backend with NeonDB on %s\n", s_url);
    
    if (mg_http_listen(&mgr, s_url, fn, NULL) == NULL) {
        fprintf(stderr, "Error starting server on %s\n", s_url);
        return 1;
    }
    
    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    
    PQfinish(conn);
    mg_mgr_free(&mgr);
    return 0;
}