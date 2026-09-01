{
  description = "Modern forensic disk imaging, damaged media rescue and conversion CLI/TUI tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfdisk = pkgs.callPackage ./package.nix { };
      in
      {
        packages = {
          default = dfdisk;
          dfdisk = dfdisk;
        };

        apps = {
          default = flake-utils.lib.mkApp {
            drv = dfdisk;
          };
          dfdisk = flake-utils.lib.mkApp {
            drv = dfdisk;
          };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ dfdisk ];
          buildInputs = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            cargo-deb
          ];
        };
      }
    );
}
