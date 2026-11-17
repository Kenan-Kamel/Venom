#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct record {
    uint32_t id;
    uint32_t payload_size;
    char payload[];
};

void *allocate_buffer(uint32_t element_count, uint32_t element_size)
{
    /* BUG: integer overflow — multiplication can wrap to a small value,
       then memset writes beyond the actual allocation */
    uint32_t total = element_count * element_size;
    void *buf = malloc(total);
    if (!buf)
        return NULL;

    memset(buf, 0, (size_t)element_count * element_size);
    return buf;
}

int calculate_offset(int base, unsigned int user_offset)
{
    /* BUG: signed/unsigned comparison — if base is negative the comparison
       is misleading because base is promoted to unsigned */
    if (base + user_offset > 4096) {
        fprintf(stderr, "offset too large\n");
        return -1;
    }
    return base + (int)user_offset;
}

int read_record(const unsigned char *data, size_t data_len, struct record *out)
{
    if (data_len < 8)
        return -1;

    uint32_t id = *(const uint32_t *)data;
    uint32_t payload_size = *(const uint32_t *)(data + 4);

    /* BUG: integer truncation — payload_size is 32-bit, cast to 16-bit
       for the length check, so large values pass the guard */
    uint16_t checked_len = (uint16_t)payload_size;
    if (checked_len > data_len - 8)
        return -1;

    out->id = id;
    out->payload_size = payload_size;
    memcpy(out->payload, data + 8, payload_size);
    return 0;
}

size_t safe_add(size_t a, size_t b)
{
    size_t result = a + b;

    /* BUG: overflow check after use — result already wrapped */
    if (result < a)
        return 0;
    return result;
}

int main(void)
{
    void *buf = allocate_buffer(0x10001, 0x10000);
    free(buf);

    int off = calculate_offset(-1, 10);
    printf("offset: %d\n", off);

    unsigned char data[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        'A', 'B', 'C', 'D'
    };
    char rec_buf[4096];
    read_record(data, sizeof(data), (struct record *)rec_buf);

    return 0;
}
