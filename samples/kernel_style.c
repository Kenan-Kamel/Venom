#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Kernel API stubs */
typedef unsigned long size_t_k;
typedef int spinlock_t;
typedef int mutex_t;

static int _copy_from_user(void *to, const void *from, size_t_k n) {
    if (!from) return -1;
    memcpy(to, from, n);
    return 0;
}
#define copy_from_user(to, from, n) _copy_from_user(to, from, n)

static void mutex_lock(mutex_t *m) { (void)m; }
static void mutex_unlock(mutex_t *m) { (void)m; }

static void *kmalloc(size_t sz) { return malloc(sz); }
static void kfree(void *p) { free(p); }

#define IOCTL_SET_CONFIG 0x1001
#define IOCTL_GET_STATUS 0x1002
#define IOCTL_RESET      0x1003
#define MAX_CONFIG_LEN 128

struct device_config {
    unsigned int flags;
    unsigned int mode;
    char name[MAX_CONFIG_LEN];
};

struct device_state {
    mutex_t lock;
    struct device_config config;
    int ref_count;
    char *dma_buffer;
};

static struct device_state g_dev;

int handle_set_config(struct device_state *dev, const void *user_arg)
{
    struct device_config new_cfg;

    /* BUG: copy_from_user return value not checked — if the copy fails,
       new_cfg contains uninitialized stack data that gets applied */
    copy_from_user(&new_cfg, user_arg, sizeof(new_cfg));

    mutex_lock(&dev->lock);
    dev->config = new_cfg;
    mutex_unlock(&dev->lock);

    return 0;
}

int handle_get_status(struct device_state *dev, void *user_buf)
{
    /* BUG: leaks kernel stack data — status_buf is not fully initialized
       before being copied out */
    char status_buf[256];
    snprintf(status_buf, 64, "mode=%u flags=%u",
             dev->config.mode, dev->config.flags);

    memcpy(user_buf, status_buf, sizeof(status_buf));
    return 0;
}

int device_ioctl(struct device_state *dev, unsigned int cmd, void *arg)
{
    /* BUG: no bounds validation on cmd — falls through to default
       without error, and IOCTL_RESET frees without nulling pointer */
    switch (cmd) {
    case IOCTL_SET_CONFIG:
        return handle_set_config(dev, arg);
    case IOCTL_GET_STATUS:
        return handle_get_status(dev, arg);
    case IOCTL_RESET:
        mutex_lock(&dev->lock);
        kfree(dev->dma_buffer);
        /* BUG: dev->dma_buffer not set to NULL — later use is UAF */
        dev->ref_count = 0;
        mutex_unlock(&dev->lock);
        return 0;
    }
    return -EINVAL;
}

int device_open(struct device_state *dev)
{
    mutex_lock(&dev->lock);

    dev->dma_buffer = kmalloc(4096);
    if (!dev->dma_buffer) {
        /* BUG: mutex not unlocked on error path — deadlock */
        return -ENOMEM;
    }

    dev->ref_count++;
    mutex_unlock(&dev->lock);
    return 0;
}

int main(void)
{
    memset(&g_dev, 0, sizeof(g_dev));

    if (device_open(&g_dev) < 0) {
        fprintf(stderr, "open failed\n");
        return 1;
    }

    struct device_config cfg = { .flags = 1, .mode = 2 };
    strncpy(cfg.name, "test-device", sizeof(cfg.name) - 1);
    device_ioctl(&g_dev, IOCTL_SET_CONFIG, &cfg);

    char status[256];
    device_ioctl(&g_dev, IOCTL_GET_STATUS, status);
    printf("status: %s\n", status);

    device_ioctl(&g_dev, IOCTL_RESET, NULL);

    kfree(g_dev.dma_buffer);
    return 0;
}
