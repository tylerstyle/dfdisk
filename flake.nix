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
        dfdisk = pkgs.callPackage ./package.nix {
          dfcoreSrc = dfcore;
          dfdiskRev = self.rev or self.dirtyRev or null;
          dfcoreRev = dfcore.rev or null;
        };
      in
      {
        packages = {
          default = dfdisk;
          dfdisk = dfdisk;
        };

        # `nix flake check` builds the package, which runs the test suite with
        # the real libewf and ddrescue (DFDISK_REQUIRE_TOOLS=1)
        checks.default = dfdisk;

        apps = {
          default = flake-utils.lib.mkApp {
            drv = dfdisk;
          };
          dfdisk = flake-utils.lib.mkApp {
            drv = dfdisk;
          };
        };

        # cargo, clippy, rustfmt, cargo-deb and every tool dfdisk runs. Cargo
        # needs the dfcore checkout next to this one (../dfcore).
        devShells.default = pkgs.mkShell {
          inputsFrom = [ dfdisk ];
          packages = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            cargo-deb
          ] ++ dfdisk.runtimeTools;
        };
      }
    );
}
