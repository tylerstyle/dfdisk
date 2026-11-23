{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = with pkgs; [
    rustc
    cargo
    rustfmt
    clippy
    cargo-deb
    libewf
    ddrescue
    smartmontools
    util-linux
    systemd
    hdparm
    nvme-cli
  ];
}
