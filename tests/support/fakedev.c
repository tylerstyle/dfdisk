/*
 * fakedev.c - LD_PRELOAD shim for dfdisk's E01 tests.
 *
 * Makes a program (ewfacquire, through libsmdev) see a regular image file as
 * a block device, and makes chosen byte ranges of that file fail with EIO, so
 * the read-error handling of ewfacquire and dfdisk can be tested end to end
 * without a failing disk, root, or device-mapper. Only reads are changed;
 * nothing is written.
 *
 * Build: cc -shared -fPIC -O2 -o fakedev.so fakedev.c -ldl
 *
 * Environment (read once, at the first intercepted call):
 *   FAKEDEV_TARGET    path of the image file that plays the device (required)
 *   FAKEDEV_PROG      act only inside the program with this short name
 *                     (default: any program)
 *   FAKEDEV_BAD       comma-separated "offset:length" byte ranges whose reads
 *                     fail with EIO (e.g. "1048576:512,2097152:4096")
 *   FAKEDEV_DIE_AT    byte offset from which every read fails with EIO (the
 *                     medium was lost)
 *   FAKEDEV_VANISH    with FAKEDEV_DIE_AT: rename the image to
 *                     "<target>.vanished" at the first read at or beyond that
 *                     offset, so the "device node" disappears while the
 *                     program keeps its descriptor (a detached USB disk)
 *   FAKEDEV_DELAY_US  sleep this long in every read of the image (abort tests)
 *   FAKEDEV_SECTOR    logical and physical sector size reported (default 512)
 *
 * The image is recognised by device and inode number, so descriptors opened
 * before a FAKEDEV_VANISH rename stay recognised. A read that starts before a
 * failing range returns the bytes up to the range (a short read), like a disk
 * whose request is split at the bad sector; a read that starts inside fails
 * with EIO and leaves the file offset unchanged, like the kernel does.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

extern char *program_invocation_short_name;

#define MAX_RANGES 64

static int initialised;
static int enabled;
static dev_t target_dev;
static ino_t target_ino;
static char target_path[4096];
static long long bad_off[MAX_RANGES];
static long long bad_len[MAX_RANGES];
static int bad_count;
static long long die_at = -1;
static int vanish;
static int vanished;
static long delay_us;
static int sector_size = 512;

static int (*real_stat)(const char *, struct stat *);
static int (*real_fstat)(int, struct stat *);
static int (*real_lstat)(const char *, struct stat *);
static int (*real_fstatat)(int, const char *, struct stat *, int);
static int (*real_ioctl)(int, unsigned long, void *);
static ssize_t (*real_read)(int, void *, size_t);
static ssize_t (*real_pread)(int, void *, size_t, off_t);
static ssize_t (*real_readv)(int, const struct iovec *, int);

static void init(void)
{
    if (initialised)
        return;
    initialised = 1;
    real_stat = dlsym(RTLD_NEXT, "stat");
    real_fstat = dlsym(RTLD_NEXT, "fstat");
    real_lstat = dlsym(RTLD_NEXT, "lstat");
    real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    real_read = dlsym(RTLD_NEXT, "read");
    real_pread = dlsym(RTLD_NEXT, "pread");
    real_readv = dlsym(RTLD_NEXT, "readv");

    const char *prog = getenv("FAKEDEV_PROG");
    if (prog && *prog && strcmp(program_invocation_short_name, prog) != 0)
        return;
    const char *target = getenv("FAKEDEV_TARGET");
    if (!target || !*target || !realpath(target, target_path))
        return;
    struct stat st;
    if (!real_stat || real_stat(target_path, &st) != 0)
        return;
    target_dev = st.st_dev;
    target_ino = st.st_ino;

    const char *bad = getenv("FAKEDEV_BAD");
    while (bad && *bad && bad_count < MAX_RANGES) {
        char *end;
        long long off = strtoll(bad, &end, 10);
        if (*end != ':')
            break;
        long long len = strtoll(end + 1, &end, 10);
        if (len > 0) {
            bad_off[bad_count] = off;
            bad_len[bad_count] = len;
            bad_count++;
        }
        bad = (*end == ',') ? end + 1 : NULL;
    }
    const char *die = getenv("FAKEDEV_DIE_AT");
    if (die && *die)
        die_at = strtoll(die, NULL, 10);
    vanish = getenv("FAKEDEV_VANISH") != NULL;
    const char *delay = getenv("FAKEDEV_DELAY_US");
    if (delay && *delay)
        delay_us = strtol(delay, NULL, 10);
    const char *sector = getenv("FAKEDEV_SECTOR");
    if (sector && *sector && atoi(sector) >= 512)
        sector_size = atoi(sector);
    enabled = 1;
}

static int is_target_stat(const struct stat *st)
{
    return enabled && st->st_dev == target_dev && st->st_ino == target_ino;
}

static int fd_is_target(int fd)
{
    struct stat st;
    init();
    if (!enabled || !real_fstat || real_fstat(fd, &st) != 0)
        return 0;
    return is_target_stat(&st);
}

static void as_block_device(struct stat *st)
{
    st->st_mode = (st->st_mode & ~S_IFMT) | S_IFBLK;
    st->st_rdev = makedev(254, 254);
}

int stat(const char *path, struct stat *st)
{
    init();
    int r = real_stat(path, st);
    if (r == 0 && is_target_stat(st))
        as_block_device(st);
    return r;
}

int stat64(const char *path, struct stat64 *st) __attribute__((alias("stat")));

int lstat(const char *path, struct stat *st)
{
    init();
    int r = real_lstat(path, st);
    if (r == 0 && is_target_stat(st))
        as_block_device(st);
    return r;
}

int lstat64(const char *path, struct stat64 *st) __attribute__((alias("lstat")));

int fstat(int fd, struct stat *st)
{
    init();
    int r = real_fstat(fd, st);
    if (r == 0 && is_target_stat(st))
        as_block_device(st);
    return r;
}

int fstat64(int fd, struct stat64 *st) __attribute__((alias("fstat")));

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
    init();
    int r = real_fstatat(dirfd, path, st, flags);
    if (r == 0 && is_target_stat(st))
        as_block_device(st);
    return r;
}

int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags)
    __attribute__((alias("fstatat")));

int ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    init();
    if (fd_is_target(fd)) {
        struct stat st;
        real_fstat(fd, &st);
        /* Callers may sign-extend the request number: compare 32 bits */
        switch ((unsigned int)request) {
        case 0x80081272u: /* BLKGETSIZE64 */
            *(uint64_t *)arg = (uint64_t)st.st_size;
            return 0;
        case 0x1260u: /* BLKGETSIZE, always in 512-byte units */
            *(unsigned long *)arg = (unsigned long)(st.st_size / 512);
            return 0;
        case 0x1268u: /* BLKSSZGET */
        case 0x127bu: /* BLKPBSZGET */
            *(int *)arg = sector_size;
            return 0;
        default:
            errno = ENOTTY;
            return -1;
        }
    }
    return real_ioctl(fd, request, arg);
}

/*
 * How many bytes of a read of `count` at `off` succeed: `count` when the read
 * touches no failing byte, else the distance to the first failing byte (0:
 * the read fails with EIO).
 */
static size_t readable(long long off, size_t count, int *dying)
{
    long long end = off + (long long)count;
    long long first_bad = end;
    *dying = 0;
    for (int i = 0; i < bad_count; i++) {
        long long b = bad_off[i], e = bad_off[i] + bad_len[i];
        if (end <= b || off >= e)
            continue;
        long long f = b > off ? b : off;
        if (f < first_bad)
            first_bad = f;
    }
    if (die_at >= 0 && end > die_at) {
        long long f = die_at > off ? die_at : off;
        if (f <= first_bad) {
            first_bad = f;
            *dying = 1;
        }
    }
    return (size_t)(first_bad - off);
}

static void lose_medium(void)
{
    if (vanish && !vanished) {
        char gone[4200];
        vanished = 1;
        snprintf(gone, sizeof gone, "%s.vanished", target_path);
        rename(target_path, gone);
    }
}

/* 0: proceed with `*count` bytes; -1: fail with EIO */
static int filter(long long off, size_t *count)
{
    int dying;
    if (delay_us > 0)
        usleep((useconds_t)delay_us);
    size_t ok = readable(off, *count, &dying);
    if (ok == 0 && *count > 0) {
        if (dying)
            lose_medium();
        errno = EIO;
        return -1;
    }
    *count = ok;
    return 0;
}

ssize_t read(int fd, void *buf, size_t count)
{
    init();
    if (fd_is_target(fd)) {
        off_t off = lseek(fd, 0, SEEK_CUR);
        if (off >= 0 && filter((long long)off, &count) < 0)
            return -1;
    }
    return real_read(fd, buf, count);
}

ssize_t pread(int fd, void *buf, size_t count, off_t off)
{
    init();
    if (fd_is_target(fd) && filter((long long)off, &count) < 0)
        return -1;
    return real_pread(fd, buf, count, off);
}

ssize_t pread64(int fd, void *buf, size_t count, off_t off) __attribute__((alias("pread")));

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    init();
    if (fd_is_target(fd)) {
        /* Rare for block reads: serve the first buffer through read() */
        if (iovcnt <= 0)
            return 0;
        return read(fd, iov[0].iov_base, iov[0].iov_len);
    }
    return real_readv(fd, iov, iovcnt);
}
