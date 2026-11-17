#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct message {
    int type;
    int length;
    char data[256];
};

struct session {
    int id;
    char *username;
    char *token;
};

struct message *parse_message(const char *raw, size_t len)
{
    struct message *msg = malloc(sizeof(*msg));
    if (!msg)
        return NULL;

    if (len < 8) {
        /* BUG: memory leak — msg is not freed on this error path */
        return NULL;
    }

    memcpy(msg, raw, len < sizeof(*msg) ? len : sizeof(*msg));
    return msg;
}

void connection_handler(const char *data, size_t len)
{
    struct session *sess = malloc(sizeof(*sess));
    sess->username = strdup("admin");

    if (len == 0) {
        free(sess->username);
        free(sess);
    }

    /* BUG: use-after-free — sess may have been freed above */
    printf("session id: %d, user: %s\n", sess->id, sess->username);
}

void close_session(struct session *sess)
{
    free(sess->token);
    free(sess->username);
    free(sess);

    /* BUG: double free — sess->token freed again through dangling pointer */
    if (sess->token)
        free(sess->token);
}

int process_batch(const char **items, int count)
{
    /* BUG: null-pointer dereference — malloc return not checked */
    int *results = malloc(count * sizeof(int));
    for (int i = 0; i < count; i++)
        results[i] = strlen(items[i]);

    int total = 0;
    for (int i = 0; i < count; i++)
        total += results[i];

    free(results);
    return total;
}

void log_event(int event_type)
{
    int severity;

    /* BUG: uninitialized variable — severity used without assignment on some paths */
    if (event_type == 1)
        severity = 5;
    else if (event_type == 2)
        severity = 3;

    printf("event=%d severity=%d\n", event_type, severity);
}

int main(void)
{
    const char raw[] = "AAAA\x10\x00\x00\x00hello world";
    struct message *msg = parse_message(raw, sizeof(raw));
    if (msg) {
        printf("type=%d\n", msg->type);
        free(msg);
    }

    connection_handler("test", 0);
    log_event(7);

    return 0;
}
