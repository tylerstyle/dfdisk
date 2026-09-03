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

rustPlatform.buildRustPackage rec {
  pname = "dfdisk";
  version = "0.1.2";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./tests
      ./README.md
      ./LICENSE
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

  meta = with lib; {
    description = "Modern forensic disk imaging, damaged media rescue and conversion CLI/TUI tool";
    homepage = "https://github.com/tylerstyle/dfdisk";
    license = licenses.gpl3Plus;
    maintainers = [ ];
    mainProgram = "dfdisk";
    platforms = platforms.linux;
  };
}
