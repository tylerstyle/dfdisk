#!/usr/bin/env bash
# Run the whole dfdisk test suite against Ubuntu 22.04's external tools, as a
# non-root user, like the CI test job: ewf-tools 20140807 and gddrescue 1.23
# are the packages of the CI runner and the .deb's dependency target.
#
# The test binaries are built on this host (`cargo test --locked --no-run`)
# and run in a container (podman, else docker) made FROM ubuntu:22.04 with
# ewf-tools, gddrescue and a C compiler (the tests compile their LD_PRELOAD
# shim there). The binaries have to run on Ubuntu 22.04: a Nix toolchain
# works (/nix/store is mounted read-only), so does a host with glibc 2.35 or
# older.
#
# Usage: scripts/test-ubuntu.sh [NAME...]
#   NAME: run only the test binaries whose file name starts with NAME
#   (e.g. ewf_e2e_test dfdisk); default: all of them.
# Exit status: 0 when every test passed.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
image=localhost/dfdisk-test-ubuntu:22.04

if command -v podman >/dev/null 2>&1; then
    engine=podman
    user_opts=(--userns=keep-id --user "$(id -u):$(id -g)")
elif command -v docker >/dev/null 2>&1; then
    engine=docker
    user_opts=(--user "$(id -u):$(id -g)")
else
    echo "test-ubuntu: neither podman nor docker is installed" >&2
    exit 1
fi

"$engine" build -q -t "$image" - >/dev/null <<'CONTAINERFILE'
FROM docker.io/library/ubuntu:22.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ewf-tools gddrescue gcc libc6-dev util-linux \
 && rm -rf /var/lib/apt/lists/*
CONTAINERFILE

cd "$repo"
cargo test --locked --no-run
mapfile -t binaries < <(
    cargo test --locked --no-run --message-format=json 2>/dev/null |
        grep '"reason":"compiler-artifact"' | grep -E '"profile":\{[^}]*"test":true' |
        sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | sort
)
if [ "$#" -gt 0 ]; then
    selected=()
    for b in "${binaries[@]}"; do
        for name in "$@"; do
            case $(basename "$b") in "$name"-*) selected+=("$b") ;; esac
        done
    done
    binaries=("${selected[@]}")
fi
if [ "${#binaries[@]}" -eq 0 ]; then
    echo "test-ubuntu: no test binary to run (does cargo test --no-run build?)" >&2
    exit 1
fi

# dfdisk refuses tmpfs destinations: the tests' scratch space is on disk
target=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
scratch="$target/ubuntu-22.04-tmp"
mkdir -p "$scratch"

mounts=(-v "$repo:$repo" -v "$target:$target")
[ -d /nix/store ] && mounts+=(-v /nix/store:/nix/store:ro)
[ -d "$repo/../dfcore" ] && mounts+=(-v "$(cd "$repo/../dfcore" && pwd):$(cd "$repo/../dfcore" && pwd):ro")

# The script below runs in the container: its $ are not this shell's
# shellcheck disable=SC2016
"$engine" run --rm --security-opt label=disable "${user_opts[@]}" "${mounts[@]}" \
    -e DFDISK_REQUIRE_TOOLS=1 -e TMPDIR="$scratch" -e HOME="$scratch" \
    -w "$repo" "$image" bash -c '
        ewfacquire -V | head -n 1
        ddrescue --version | head -n 1
        echo "user: $(id -u) ($(id -un 2>/dev/null || echo unnamed))"
        failed=0 passed=0 failing=0
        for b in "$@"; do
            name=$(basename "$b" | sed "s/-[0-9a-f]*$//")
            if out=$("$b" 2>&1); then status=ok; else status=FAILED; failing=$((failing + 1)); fi
            result=$(printf "%s\n" "$out" | grep "^test result" | tail -n 1)
            echo "$name: $status: $result"
            printf "%s\n" "$out" | grep -E "^test .* FAILED$" | sed "s/^/    /" || true
            if [ "$status" = FAILED ]; then
                printf "%s\n" "$out" | sed -n "/^failures:/,/^test result/p" | head -n 200
            fi
            p=$(printf "%s\n" "$result" | sed -n "s/.* \([0-9]*\) passed.*/\1/p")
            f=$(printf "%s\n" "$result" | sed -n "s/.* \([0-9]*\) failed.*/\1/p")
            passed=$((passed + ${p:-0})); failed=$((failed + ${f:-0}))
        done
        echo "total: $passed passed, $failed failed, $failing failing test binaries"
        [ "$failing" -eq 0 ]
    ' test-ubuntu "${binaries[@]}"
