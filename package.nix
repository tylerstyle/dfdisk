{ lib
, stdenv
, rustPlatform
, runCommand
, makeWrapper
  # External tools dfdisk runs. None is linked: they go on the wrapper's PATH
  # only (and, where tests need them, into the check phase).
, libewf # ewfacquire, ewfverify, ewfinfo, ewfexport
, ddrescue
, smartmontools # smartctl
, util-linux # lsblk, umount
, systemd # udevadm, timedatectl
, hdparm # hdparm -N, --dco-identify (HPA/DCO, read-only queries)
, nvme-cli # nvme id-ns
  # dfcore is a sibling path dependency (../dfcore); flakes pass their input
, dfcoreSrc ? ../dfcore
  # Source revisions embedded in the binary and every report (`dfdisk --version`);
  # the flake passes its own and the dfcore input's revision
, dfdiskRev ? null
, dfcoreRev ? null
}:

let
  runtimeTools = [
    libewf
    ddrescue
    smartmontools
    util-linux
    systemd
    hdparm
    nvme-cli
  ];

  ownSrc = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./build.rs
      ./src
      ./tests
      ./README.md
      ./LICENSE
      ./LICENSE-MIT
      ./LICENSE-APACHE
    ];
  };
  coreSrc = lib.cleanSourceWith {
    filter = path: type: baseNameOf path != "target";
    src = lib.cleanSource dfcoreSrc;
  };
  # Lay out the sources as in ~/git so `path = "../dfcore"` resolves
  src = runCommand "dfdisk-src" { } ''
    mkdir -p $out
    cp -r ${ownSrc} $out/dfdisk
    cp -r ${coreSrc} $out/dfcore
    chmod -R u+w $out
  '';
in
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "dfdisk";
  version = "0.2.0";

  inherit src;
  sourceRoot = "dfdisk-src/dfdisk";

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  # build.rs cannot run git in the sandbox: take the revisions from here
  env = {
    DFDISK_GIT_REV = if dfdiskRev != null then dfdiskRev else "unknown";
    DFCORE_GIT_REV = if dfcoreRev != null then dfcoreRev else "unknown";
  };

  nativeBuildInputs = [
    makeWrapper
  ];

  # Tests that need external tools run against the real ones here: libewf
  # (E01 engine, converter, verify), ddrescue (rescue engine) and a C compiler
  # for the LD_PRELOAD fake-device shim. DFDISK_REQUIRE_TOOLS=1 turns a missing
  # tool into a failing test instead of a skipped one.
  nativeCheckInputs = [
    libewf
    ddrescue
    stdenv.cc
  ];

  preCheck = ''
    export DFDISK_REQUIRE_TOOLS=1
  '';

  postInstall = ''
    wrapProgram $out/bin/dfdisk \
      --prefix PATH : ${lib.makeBinPath runtimeTools}
  '';

  passthru = {
    # The wrapper's PATH; the NUR recipe has to list the same tools
    inherit runtimeTools;
  };

  meta = {
    description = "Modern forensic disk imaging, damaged media rescue and conversion CLI/TUI tool";
    homepage = "https://github.com/tylerstyle/dfdisk";
    license = with lib.licenses; [ mit asl20 ];
    maintainers = [ ];
    mainProgram = "dfdisk";
    platforms = lib.platforms.linux;
  };
})
