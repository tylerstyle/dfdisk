{
  description = "Modern forensic disk imaging, damaged media rescue and conversion CLI/TUI tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Shared safety core, a sibling Cargo path dependency
    dfcore = {
      url = "github:tylerstyle/dfcore";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, dfcore }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfdisk = pkgs.callPackage ./package.nix { dfcoreSrc = dfcore; };
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
