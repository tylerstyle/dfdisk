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
}:

let
  ownSrc = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
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
