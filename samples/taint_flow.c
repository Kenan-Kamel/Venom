#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CMD_BUF_SIZE 128
#define DATA_BUF_SIZE 64

int receive_request(int fd, char *out, size_t out_size)
{
    char raw[512];

    ssize_t n = read(fd, raw, sizeof(raw) - 1);
    if (n <= 0)
        return -1;
    raw[n] = '\0';

    /* BUG: tainted data from read() copied with strcpy — no bounds check
       relative to out_size */
    strcpy(out, raw);
    return 0;
}

void process_filename(int fd)
{
    char filename[DATA_BUF_SIZE];

    if (receive_request(fd, filename, sizeof(filename)) < 0)
        return;

    /* BUG: command injection — tainted filename concatenated into
       a shell command string */
    char cmd[CMD_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "cat %s", filename);
    system(cmd);
}

void load_config(void)
{
    char buf[64];

    /* BUG: getenv() value used without length check — environment
       variable can exceed buf size */
    const char *home = getenv("HOME");
    if (home)
        strcpy(buf, home);

    char path[128];
    snprintf(path, sizeof(path), "%s/.venomrc", buf);
    FILE *f = fopen(path, "r");
    if (f)
        fclose(f);
}

void echo_service(int sockfd)
{
    char input[256];
    ssize_t n = read(sockfd, input, sizeof(input) - 1);
    if (n <= 0)
        return;
    input[n] = '\0';

    /* BUG: tainted network data used as format string */
    fprintf(stdout, input);
}

int main(void)
{
    process_filename(STDIN_FILENO);
    load_config();
    echo_service(STDIN_FILENO);
    return 0;
}
