/*
 * LD_PRELOAD shim that answers NVMe admin commands for one regular file as
 * an emulated NVMe namespace (nsid 1), so the real nvme-cli and smartctl
 * binaries print their real JSON for it. Used only to capture the fixtures
 * next to this file; never against a device.
 *
 *   NVME_EMUL_FILE   absolute path of the image file standing in for the namespace
 *   NVME_EMUL_NSZE   namespace size in logical blocks (format 0: 512 bytes)
 *   NVME_EMUL_USED   percentage_used of the SMART / health log
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NVME_IOCTL_ID 0x4e40UL
#define NVME_IOCTL_ADMIN_CMD 0xc0484e41UL
#define NVME_IOCTL_ADMIN64_CMD 0xc0504e47UL

struct passthru {
    uint8_t opcode, flags; uint16_t rsvd1; uint32_t nsid, cdw2, cdw3;
    uint64_t metadata, addr; uint32_t metadata_len, data_len;
    uint32_t cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, timeout_ms;
};

static int match(const char *path) {
    const char *t = getenv("NVME_EMUL_FILE");
    char rp[4096];
    return t && path && realpath(path, rp) && strcmp(rp, t) == 0;
}
static int fd_match(int fd) {
    char p[64], buf[4096];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(p, buf, sizeof buf - 1);
    if (n < 0) return 0;
    buf[n] = 0;
    return getenv("NVME_EMUL_FILE") && strcmp(buf, getenv("NVME_EMUL_FILE")) == 0;
}
static uint64_t env_u64(const char *k, uint64_t d) { const char *s = getenv(k); return s ? strtoull(s, 0, 10) : d; }

#define BLK(st) ((st)->st_mode = ((st)->st_mode & ~S_IFMT) | S_IFBLK, (st)->st_rdev = makedev(259, 0))
#include <sys/sysmacros.h>
int fstat(int fd, struct stat *st) {
    static int (*real)(int, struct stat *);
    if (!real) real = dlsym(RTLD_NEXT, "fstat");
    int r = real(fd, st);
    if (!r && fd_match(fd)) BLK(st);
    return r;
}
int fstat64(int fd, struct stat64 *st) {
    static int (*real)(int, struct stat64 *);
    if (!real) real = dlsym(RTLD_NEXT, "fstat64");
    int r = real(fd, st);
    if (!r && fd_match(fd)) BLK(st);
    return r;
}
int stat(const char *p, struct stat *st) {
    static int (*real)(const char *, struct stat *);
    if (!real) real = dlsym(RTLD_NEXT, "stat");
    int r = real(p, st);
    if (!r && match(p)) BLK(st);
    return r;
}
int stat64(const char *p, struct stat64 *st) {
    static int (*real)(const char *, struct stat64 *);
    if (!real) real = dlsym(RTLD_NEXT, "stat64");
    int r = real(p, st);
    if (!r && match(p)) BLK(st);
    return r;
}

static void put(uint8_t *b, int off, uint64_t v, int len) { for (int i = 0; i < len; i++) b[off + i] = (v >> (8 * i)) & 0xff; }
static void str(uint8_t *b, int off, const char *s, int len) { memset(b + off, ' ', len); memcpy(b + off, s, strlen(s) < (size_t)len ? strlen(s) : (size_t)len); }

static int admin(struct passthru *c) {
    uint8_t *b = (uint8_t *)(uintptr_t)c->addr;
    uint64_t nsze = env_u64("NVME_EMUL_NSZE", 1953525168);
    if (c->opcode == 0x06) {                                 /* Identify */
        memset(b, 0, c->data_len);
        unsigned cns = c->cdw10 & 0xff;
        if (cns == 1) {                                      /* controller */
            put(b, 0, 0x1e0f, 2); put(b, 2, 0x1e0f, 2);
            str(b, 4, "EMUL0000000000000001", 20);
            str(b, 24, "EMULATED NVME SSD 1TB", 40);
            str(b, 64, "1.0", 8);
            put(b, 80, 0x00010400, 4);                       /* NVMe 1.4 */
            put(b, 262, 63, 1);                              /* elpe */
            put(b, 266, 353, 2); put(b, 268, 358, 2);        /* wctemp, cctemp */
            put(b, 280, nsze * 512, 8);                      /* tnvmcap */
            put(b, 512, 0x66, 1); put(b, 513, 0x44, 1);      /* sqes, cqes */
            put(b, 516, 1, 4);                               /* nn */
            return 0;
        }
        if (cns == 0 && c->nsid == 1) {                      /* namespace */
            put(b, 0, nsze, 8); put(b, 8, nsze, 8); put(b, 16, nsze / 4, 8);
            put(b, 25, 0, 1); put(b, 26, 0, 1);              /* nlbaf 0 (one format), flbas 0 */
            put(b, 128, 0, 2); put(b, 130, 9, 1); put(b, 131, 0, 1);
            return 0;
        }
        return 0x400b;                                       /* invalid namespace or format */
    }
    if (c->opcode == 0x02) {                                 /* Get Log Page */
        memset(b, 0, c->data_len);
        unsigned lid = c->cdw10 & 0xff;
        if (lid == 0x02) {
            put(b, 1, 310, 2);                               /* 37 C */
            put(b, 3, 100, 1); put(b, 4, 10, 1);
            put(b, 5, env_u64("NVME_EMUL_USED", 3), 1);
            put(b, 32, 123456, 8); put(b, 48, 654321, 8);
            put(b, 112, 42, 8); put(b, 128, 1234, 8); put(b, 144, 7, 8);
            return 0;
        }
        if (lid == 0x01 || lid == 0x06) return 0;
        return 0x4109;                                       /* invalid log page */
    }
    return 0x4001;                                           /* invalid opcode */
}

int ioctl(int fd, unsigned long req, ...) {
    static int (*real)(int, unsigned long, void *);
    if (!real) real = dlsym(RTLD_NEXT, "ioctl");
    va_list ap; va_start(ap, req); void *arg = va_arg(ap, void *); va_end(ap);
    if (!fd_match(fd)) return real(fd, req, arg);
    if (getenv("NVME_EMUL_DEBUG")) fprintf(stderr, "[nvme-emul] ioctl 0x%lx\n", req);
    if (req == NVME_IOCTL_ID) return 1;
    if (req == NVME_IOCTL_ADMIN_CMD || req == NVME_IOCTL_ADMIN64_CMD) return admin(arg);
    errno = ENOTTY;
    return -1;
}
