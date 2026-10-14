{ lib
, rustPlatform
, runCommand
, makeWrapper
, pkg-config
, libewf
, smartmontools
, ddrescue
, util-linux
, systemd
  # dfcore is a sibling path dependency (../dfcore); flakes pass their input
, dfcoreSrc ? ../dfcore
  # Source revisions embedded in the binary and every report (`dfdisk --version`);
  # the flake passes its own and the dfcore input's revision
, dfdiskRev ? null
, dfcoreRev ? null
}:

let
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
  version = "0.1.10";

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
    pkg-config
    makeWrapper
    util-linux
  ];

  buildInputs = [
    libewf
    smartmontools
    ddrescue
    util-linux
    systemd
  ];

  postInstall = ''
    wrapProgram $out/bin/dfdisk \
      --prefix PATH : ${lib.makeBinPath [
        libewf
        smartmontools
        ddrescue
        util-linux
        systemd
      ]}
  '';

  meta = {
    description = "Modern forensic disk imaging, damaged media rescue and conversion CLI/TUI tool";
    homepage = "https://github.com/tylerstyle/dfdisk";
    license = with lib.licenses; [ mit asl20 ];
    maintainers = [ ];
    mainProgram = "dfdisk";
    platforms = lib.platforms.linux;
  };
})
