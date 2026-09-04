{ lib
, rustPlatform
, makeWrapper
, pkg-config
, libewf
, smartmontools
, ddrescue
, util-linux
, systemd
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "dfdisk";
  version = "0.1.4";

  src = lib.fileset.toSource {
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
