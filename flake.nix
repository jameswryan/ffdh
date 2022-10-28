{
  description = "Opionated Finite-Field Diffie-Hellman Key Exchange";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils , rust-overlay, ...}:
    flake-utils.lib.eachDefaultSystem
      (system:
        let 
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          py = pkgs.python3;
          pyWPkgs = py.withPackages (p: with p; [
            cryptography
            mypy
            python-lsp-server
            pylsp-mypy
          ]);
          in 
          with pkgs; {
          devShells.default = mkShell {
            buildInputs = [
              pkg-config
              rust-bin.nightly.latest.default
              rust-analyzer
             
            ];
          };
        }
      );
}
