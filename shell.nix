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
    dcfldd
    dc3dd
  ];
}
