Real output of libewf 20231119 (ewfacquire, ewfinfo, ewfverify), captured on
Linux with a 4 MiB random source file that tests/support/fakedev.c presented
to ewfacquire as a block device (LD_PRELOAD), with reads failing (EIO) at
chosen byte ranges. Paths are relative; nothing else was edited except that
absolute paths in ewfverify's "in segment file(s):" lines were made relative.

Directory              ewfacquire options / shim settings
one_bad_sector         -r 2 -g 1 -w -d sha1,sha256 -m fixed -M physical;
                       FAKEDEV_BAD=1048576:512 (sector 2048)
three_ranges_g8        -r 1 -g 8 -w -d sha1;
                       FAKEDEV_BAD=1049600:512,2097152:4096,3276800:70000
clean                  -r 2 -g 1 -w -d sha1,sha256 -m removable -M logical
source_vanished        -r 2 -g 1 -w; FAKEDEV_DIE_AT=1048576 FAKEDEV_VANISH=1
                       (the source node disappears at the first failing read;
                       ewfacquire stops with FAILURE)
dying_to_end           -r 2 -g 1 -w; FAKEDEV_DIE_AT=1048576 (every read from
                       1 MiB on fails; the node stays)
sector4096             -r 2 -g 1 -w; FAKEDEV_SECTOR=4096 FAKEDEV_BAD=1048576:4096
granularity_fallback   -r 2 -g 128 (ewfacquire falls back to 64)
aborted                -g 1; FAKEDEV_DELAY_US=60000; SIGINT after 3 s
slow                   -g 1; FAKEDEV_DELAY_US=60000 (progress lines)
tampered               ewfacquire -c none -d sha1,sha256 (clean source), then
                       4 bytes overwritten at file offset 2000000; ewfverify
                       -d md5,sha1,sha256 and -d sha256

Each directory holds ewfacquire.stdout/.stderr, the -l log
(img.ewfacquire.log), ewfinfo -e / -m output and ewfverify output (empty
streams are omitted).
