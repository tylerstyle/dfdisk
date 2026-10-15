#!/bin/sh
# Re-create the captured tool outputs in tests/fixtures/discovery/tools.
#
# Every file <name>.stdout / .stderr / .exit is what the REAL tool binary
# printed and returned (hdparm 9.65, smartmontools 7.5, nvme-cli 2.16 when
# captured). Drive states a test machine does not have (HPA, DCO, failing
# SMART, standby, an NVMe namespace) come from the LD_PRELOAD shims next to
# this script: they answer the tools' ATA / NVMe ioctls for a regular image
# file the way a drive would, so the tools' own parsing and printing runs.
# The failure cases (no ATA device, permission denied) are the tools run on
# plain files. No command is sent to any real device.
#
# <name>.commands lists the ATA commands a run sent (shim log), which shows
# that dfdisk's SMART policies never touch the SCT log page E0h while
# `smartctl -x` reads it.
#
# Run as a normal user (the permission cases need it), e.g.:
#   nix shell nixpkgs#hdparm nixpkgs#smartmontools nixpkgs#nvme-cli -c tests/fixtures/discovery/tools/capture.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'chmod -R u+rwx "$work"; rm -rf "$work"' EXIT
cc -shared -fPIC -O2 -o "$work/ata-emul.so" "$here/ata-emul.c" -ldl
cc -shared -fPIC -O2 -o "$work/nvme-emul.so" "$here/nvme-emul.c" -ldl
cd "$work"
truncate -s 1M sdx nvmex noperm
chmod 000 noperm

cap() {
    name=$1
    shift
    if env LC_ALL=C LANG=C "$@" >"$here/$name.stdout" 2>"$here/$name.stderr"; then
        echo 0 >"$here/$name.exit"
    else
        echo $? >"$here/$name.exit"
    fi
}
commands() {
    name=$1
    shift
    env LC_ALL=C LANG=C ATA_EMUL_DEBUG=1 "$@" 2>&1 >/dev/null | grep '^\[ata-emul\]' | sort | uniq >"$here/$name.commands" || true
}

ata="LD_PRELOAD=$work/ata-emul.so ATA_EMUL_FILE=$work/sdx"
nvme="LD_PRELOAD=$work/nvme-emul.so NVME_EMUL_FILE=$work/nvmex"
hpa="ATA_EMUL_VISIBLE=976771055 ATA_EMUL_NATIVE=976773168"
clean="ATA_EMUL_VISIBLE=976773168 ATA_EMUL_NATIVE=976773168"
basic="-j -i -H -A -l error"
full="-j -i -H -c -A -f brief -l xerror,error -l xselftest,selftest -l selective -l directory -l devstat -l defects -l sataphy -l sasphy -l background -l ssd -g all"

# shellcheck disable=SC2086
{
cap hdparm-N-hpa-enabled env $ata $hpa hdparm -N sdx
cap hdparm-N-hpa-disabled env $ata $clean hdparm -N sdx
cap hdparm-N-invalid env $ata ATA_EMUL_VISIBLE=976773168 ATA_EMUL_NATIVE=976771055 ATA_EMUL_DCO_REAL=976773168 hdparm -N sdx
cap hdparm-N-not-identified hdparm -N sdx
cap hdparm-N-permission-denied hdparm -N noperm
cap hdparm-dco-equal env $ata $clean ATA_EMUL_DCO_REAL=976773168 hdparm --dco-identify sdx
cap hdparm-dco-above-native env $ata $clean ATA_EMUL_DCO_REAL=1953525168 hdparm --dco-identify sdx
cap hdparm-dco-unsupported env $ata $clean hdparm --dco-identify sdx
cap hdparm-dco-not-ata hdparm --dco-identify sdx
commands hdparm-N env $ata $hpa hdparm -N sdx
commands hdparm-dco env $ata $clean ATA_EMUL_DCO_REAL=976773168 hdparm --dco-identify sdx

cap nvme-id-ns env $nvme NVME_EMUL_NSZE=1953525168 nvme id-ns -o json nvmex
cap nvme-id-ns-not-block nvme id-ns -o json sdx

cap smartctl-ata-passed env $ata $clean smartctl $basic -d ata sdx
cap smartctl-ata-failed env $ata $clean ATA_EMUL_SMART=fail smartctl $basic -d ata sdx
cap smartctl-ata-standby env $ata $clean ATA_EMUL_POWER=standby smartctl $basic -n standby -d ata sdx
cap smartctl-ata-full env $ata $clean smartctl $full -d ata sdx
cap smartctl-nvme env $nvme NVME_EMUL_NSZE=1953525168 NVME_EMUL_USED=3 smartctl $basic -d nvme nvmex
cap smartctl-scsi-inquiry-failed smartctl $basic sdx
cp sdx img.bin
cap smartctl-unknown-type smartctl $basic img.bin
cap smartctl-permission-denied smartctl $basic -d sat noperm
cap smartctl-sat-no-identify smartctl $basic -d sat sdx
commands smartctl-basic env $ata $clean ATA_EMUL_SCT=1 smartctl $basic -d ata sdx
commands smartctl-full env $ata $clean ATA_EMUL_SCT=1 smartctl $full -d ata sdx
commands smartctl-x env $ata $clean ATA_EMUL_SCT=1 smartctl -j -x -d ata sdx
}
hdparm -V >"$here/versions.txt" 2>&1
smartctl --version | head -n 1 >>"$here/versions.txt"
nvme version >>"$here/versions.txt"
