/*
 * LD_PRELOAD shim that answers hdparm's ATA commands for one regular file as
 * an emulated drive, so the real hdparm binary prints its real output for
 * drive states a test machine does not have (HPA set, DCO, both). Used only
 * to capture the fixtures next to this file; never against a device.
 *
 *   ATA_EMUL_FILE     absolute path of the image file standing in for the drive
 *   ATA_EMUL_VISIBLE  sectors IDENTIFY reports (what the OS sees)
 *   ATA_EMUL_NATIVE   READ NATIVE MAX ADDRESS + 1
 *   ATA_EMUL_DCO_REAL DEVICE CONFIGURATION IDENTIFY real max + 1 (unset: the
 *                     command aborts with EIO, as on drives without DCO)
 *   ATA_EMUL_SMART    "pass" (default) or "fail": SMART data for smartctl -d ata
 *   ATA_EMUL_POWER    "standby": CHECK POWER MODE reports standby
 *   ATA_EMUL_SCT      set: IDENTIFY advertises SCT (to show which runs send SCT)
 *   ATA_EMUL_DEBUG    set: log every ATA command to stderr
 *
 * SG_IO fails with EINVAL, so hdparm uses the legacy HDIO_DRIVE_CMD /
 * HDIO_DRIVE_TASKFILE ioctls, answered here like the kernel would.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SG_IO 0x2285
#define HDIO_DRIVE_CMD 0x031f
#define HDIO_DRIVE_TASKFILE 0x031d
#define HDIO_DRIVE_TASK 0x031e

struct regs { uint8_t data, feat, nsect, lbal, lbam, lbah, dev, command; };
struct taskfile { struct regs lob, hob; /* flags, phase etc. follow */ };

static int is_target(int fd) {
    const char *t = getenv("ATA_EMUL_FILE");
    char p[64], buf[4096];
    if (!t) return 0;
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(p, buf, sizeof buf - 1);
    if (n < 0) return 0;
    buf[n] = 0;
    return strcmp(buf, t) == 0;
}

static uint64_t env_u64(const char *k) { const char *s = getenv(k); return s ? strtoull(s, 0, 10) : 0; }

static void put16(uint8_t *b, int word, uint16_t v) { b[2 * word] = v & 0xff; b[2 * word + 1] = v >> 8; }

static void identify(uint8_t *b) {
    uint64_t vis = env_u64("ATA_EMUL_VISIBLE");
    memset(b, 0, 512);
    const char *model = "EMULATED ATA DISK                       ";
    for (int i = 0; i < 20; i++) put16(b, 27 + i, (uint16_t)(model[2 * i] << 8 | model[2 * i + 1]));
    const char *serial = "EMUL-ATA-000000000001";
    const char *fw = "EMUL01  ";
    for (int i = 0; i < 10; i++) put16(b, 10 + i, (uint16_t)(serial[2 * i] << 8 | serial[2 * i + 1]));
    for (int i = 0; i < 4; i++) put16(b, 23 + i, (uint16_t)(fw[2 * i] << 8 | fw[2 * i + 1]));
    put16(b, 0, 0x0040);                                    /* fixed ATA device */
    put16(b, 49, 0x0200);                                   /* LBA */
    uint32_t lba28 = vis > 0x0fffffff ? 0x0fffffff : (uint32_t)vis;
    put16(b, 60, lba28 & 0xffff); put16(b, 61, lba28 >> 16);
    put16(b, 80, 0x01f0);                                   /* ATA-4..8, not ACS-3 */
    put16(b, 82, 0x4001);                                   /* SMART supported */
    put16(b, 83, 0x4400);                                   /* 48-bit supported */
    put16(b, 84, 0x4003);                                   /* SMART error log, self-test */
    put16(b, 85, 0x0001);                                   /* SMART enabled */
    put16(b, 86, 0x0400);                                   /* 48-bit enabled */
    put16(b, 87, 0x4003);
    put16(b, 217, 7200);                                    /* rotation rate */
    if (getenv("ATA_EMUL_SCT")) put16(b, 206, 0x003d);      /* SCT command transport + features */
    for (int i = 0; i < 4; i++) put16(b, 100 + i, (vis >> (16 * i)) & 0xffff);
}

static void dco(uint8_t *b, uint64_t real) {
    uint64_t max = real - 1;
    memset(b, 0, 512);
    put16(b, 0, 0x0002);
    put16(b, 1, 0x0007);
    put16(b, 2, 0x007f);
    put16(b, 3, max & 0xffff); put16(b, 4, (max >> 16) & 0xffff); put16(b, 5, (max >> 32) & 0xffff);
    put16(b, 7, 0x01ff);
    put16(b, 8, 0x0001);
    uint8_t sum = 0xa5;
    for (int i = 0; i < 154 * 2; i++) sum += b[i];
    b[510] = 0xa5;
    b[511] = (uint8_t)(0 - sum);
}

static int failing(void) { const char *s = getenv("ATA_EMUL_SMART"); return s && strcmp(s, "fail") == 0; }

static void checksum(uint8_t *b) { uint8_t sum = 0; for (int i = 0; i < 511; i++) sum += b[i]; b[511] = (uint8_t)(0 - sum); }

struct attr { uint8_t id; uint16_t flags; uint8_t cur, worst, thresh; uint64_t raw; };

static int attrs(struct attr *a) {
    int f = failing(), n = 0;
    a[n++] = (struct attr){5, 0x0033, f ? 12 : 100, f ? 12 : 100, 36, f ? 1584 : 0};
    a[n++] = (struct attr){9, 0x0032, 95, 95, 0, f ? 45210 : 4321};
    a[n++] = (struct attr){12, 0x0032, 100, 100, 20, 42};
    a[n++] = (struct attr){194, 0x0022, 35, 50, 0, f ? 54 : 35};
    a[n++] = (struct attr){197, 0x0012, 100, 100, 0, f ? 320 : 0};
    a[n++] = (struct attr){198, 0x0010, 100, 100, 0, f ? 112 : 0};
    return n;
}

static void smart_values(uint8_t *b) {
    struct attr a[30];
    int n = attrs(a);
    memset(b, 0, 512);
    put16(b, 0, 0x0010);
    for (int i = 0; i < n; i++) {
        uint8_t *e = b + 2 + 12 * i;
        e[0] = a[i].id; e[1] = a[i].flags & 0xff; e[2] = a[i].flags >> 8;
        e[3] = a[i].cur; e[4] = a[i].worst;
        for (int k = 0; k < 6; k++) e[5 + k] = (a[i].raw >> (8 * k)) & 0xff;
    }
    b[362] = 0x82; b[363] = 0x00; put16(b, 182, 600);        /* offline status, total time (bytes 364/365) */
    b[367] = 0x7b; b[368] = 0x03; b[370] = 0x01; b[372] = 2; b[373] = 120;
    checksum(b);
}

static void smart_thresholds(uint8_t *b) {
    struct attr a[30];
    int n = attrs(a);
    memset(b, 0, 512);
    put16(b, 0, 0x0010);
    for (int i = 0; i < n; i++) { b[2 + 12 * i] = a[i].id; b[3 + 12 * i] = a[i].thresh; }
    checksum(b);
}

static void smart_log(uint8_t *b, int log) {
    memset(b, 0, 512);
    if (log == 1) { b[0] = 1; }                              /* summary error log, no errors */
    checksum(b);
}

int ioctl(int fd, unsigned long req, ...) {
    static int (*real)(int, unsigned long, void *);
    if (!real) real = dlsym(RTLD_NEXT, "ioctl");
    va_list ap; va_start(ap, req); void *arg = va_arg(ap, void *); va_end(ap);
    if (!is_target(fd)) return real(fd, req, arg);
    if (req == SG_IO) { errno = EINVAL; return -1; }
    if (req == HDIO_DRIVE_CMD) {
        uint8_t *a = arg;
        if (getenv("ATA_EMUL_DEBUG")) fprintf(stderr, "[ata-emul] HDIO_DRIVE_CMD cmd=0x%02x feat=0x%02x nsect=0x%02x\n", a[0], a[2], a[1]);
        if (a[0] == 0xec) { identify(a + 4); a[0] = 0x50; return 0; }
        if (a[0] == 0xe5) {                                  /* CHECK POWER MODE */
            const char *p = getenv("ATA_EMUL_POWER");
            a[2] = (p && strcmp(p, "standby") == 0) ? 0x00 : 0xff; a[0] = 0x50; return 0;
        }
        if (a[0] == 0xb0 && a[2] == 0xd0) { smart_values(a + 4); a[0] = 0x50; return 0; }
        if (a[0] == 0xb0 && a[2] == 0xd1) { smart_thresholds(a + 4); a[0] = 0x50; return 0; }
        if (a[0] == 0xb0 && a[2] == 0xd5) { smart_log(a + 4, a[1]); a[0] = 0x50; return 0; }
        if (a[0] == 0xb0) { a[0] = 0x50; return 0; }         /* other SMART subcommands: accepted */
        if (a[0] == 0xb1 && a[2] == 0xc2) {
            uint64_t real_max = env_u64("ATA_EMUL_DCO_REAL");
            if (!real_max) { errno = EIO; return -1; }
            dco(a + 4, real_max); a[0] = 0x50; return 0;
        }
        errno = EIO; return -1;
    }
    if (req == HDIO_DRIVE_TASK) {                            /* SMART RETURN STATUS */
        uint8_t *t = arg;
        if (getenv("ATA_EMUL_DEBUG")) fprintf(stderr, "[ata-emul] HDIO_DRIVE_TASK cmd=0x%02x feat=0x%02x\n", t[0], t[1]);
        if (failing()) { t[4] = 0xf4; t[5] = 0x2c; }
        return 0;
    }
    if (req == HDIO_DRIVE_TASKFILE) {
        struct taskfile *t = arg;
        if (getenv("ATA_EMUL_DEBUG")) fprintf(stderr, "[ata-emul] HDIO_DRIVE_TASKFILE cmd=0x%02x feat=0x%02x\n", t->lob.command, t->lob.feat);
        if (t->lob.command == 0x27) {                       /* READ NATIVE MAX EXT */
            uint64_t m = env_u64("ATA_EMUL_NATIVE") - 1;
            t->lob.lbal = m & 0xff; t->lob.lbam = (m >> 8) & 0xff; t->lob.lbah = (m >> 16) & 0xff;
            t->hob.lbal = (m >> 24) & 0xff; t->hob.lbam = (m >> 32) & 0xff; t->hob.lbah = (m >> 40) & 0xff;
            t->lob.command = 0x50;
            return 0;
        }
        errno = EIO; return -1;
    }
    if (getenv("ATA_EMUL_DEBUG")) fprintf(stderr, "[ata-emul] ioctl 0x%lx -> ENOTTY\n", req);
    errno = ENOTTY;
    return -1;
}
