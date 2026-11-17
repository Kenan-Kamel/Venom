#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PACKET_SIZE 64
#define HEADER_LEN 8

struct packet_header {
    unsigned int type;
    unsigned int length;
};

void process_network_packet(const char *raw_data, size_t raw_len)
{
    char local_buf[MAX_PACKET_SIZE];

    /* BUG: strcpy with no length check — stack buffer overflow */
    strcpy(local_buf, raw_data);

    struct packet_header hdr;
    memcpy(&hdr, local_buf, sizeof(hdr));

    printf("packet type=%u len=%u\n", hdr.type, hdr.length);
}

char *duplicate_payload(const char *src, unsigned int declared_len)
{
    char *heap_buf = malloc(declared_len);
    if (!heap_buf)
        return NULL;

    /* BUG: memcpy uses strlen(src) which may exceed declared_len — heap overflow */
    memcpy(heap_buf, src, strlen(src) + 1);
    return heap_buf;
}

void normalize_fields(char *fields[], int count)
{
    char normalized[256];
    int pos = 0;

    /* BUG: off-by-one — writes one byte past normalized[] when pos == 256 */
    for (int i = 0; i < count; i++) {
        size_t flen = strlen(fields[i]);
        for (size_t j = 0; j <= flen; j++) {
            normalized[pos] = fields[i][j];
            pos++;
        }
    }
    normalized[pos] = '\0';
}

void handle_user_input(const char *username)
{
    char greeting[128];
    snprintf(greeting, sizeof(greeting), "Welcome, %s", username);

    /* BUG: format-string vulnerability — user-controlled string as format */
    printf(greeting);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        return 1;

    process_network_packet(argv[1], strlen(argv[1]));
    handle_user_input(argv[1]);

    char *dup = duplicate_payload(argv[1], 16);
    free(dup);

    return 0;
}
