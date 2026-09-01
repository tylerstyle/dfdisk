{ lib
, rustPlatform
, fetchFromGitHub
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
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "tylerstyle";
    repo = "dfdisk";
    rev = "v${version}";
    hash = "sha256-MqTGszHUYO8pgqZ2aKWqZzCNY/hFJnGEXnw6c4UV3Gg=";
  };

  cargoHash = "sha256-5/YBpHqe2++e4TF2ndyyW1LJZ1sqTiMDGw6YJMoQZEg=";

  nativeBuildInputs = [
    pkg-config
    makeWrapper
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
    maintainers = with maintainers; [ tylerstyle ];
    mainProgram = "dfdisk";
    platforms = platforms.linux;
  };
}
