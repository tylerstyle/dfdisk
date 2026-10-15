{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    rustfmt
    clippy
    pkg-config
    libewf
    smartmontools
    ddrescue
    hdparm
    nvme-cli
    dcfldd
    dc3dd
  ];
}
