{
  description = "Python venv development env in nix + typst setup";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Example of downloading icons from a non-flake source
    # font-awesome = {
    #   url = "github:FortAwesome/Font-Awesome";
    #   flake = false;
    # };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      pythonPackages = pkgs.python314Packages;
    in {
      devShells.writeup = pkgs.mkShell {
        name = "typst-shell";
        buildInputs = with pkgs; [
          typst
        ];
        FONTCONFIG_FILE = pkgs.makeFontsConf {
          fontDirectories = with pkgs; [
            libertine
            inconsolata
            libertinus
            texlivePackages.inconsolata
          ];
        };
      };
      devShells.default = pkgs.mkShell {
        name = "python-venv";
        venvDir = "./.venv";
        buildInputs = with pythonPackages; [
          # A Python interpreter including the 'venv' module is required to bootstrap
          # the environment.
          python

          # This executes some shell code to initialize a venv in $venvDir before
          # dropping into the shell
          venvShellHook

          # Those are dependencies that we would like to use from nixpkgs, which will
          # add them to PYTHONPATH and thus make them accessible from within the venv.
          python-nmap
          pydantic
          langchain
          langchain-ollama
          langchain-community
          xmltodict
          sortedcontainers

          pkgs.nmap
        ];

        # Run this command, only after creating the virtual environment
        postVenvCreation = ''
          unset SOURCE_DATE_EPOCH
          pip install --upgrade pip
          pip install -r requirements.txt
        '';

        # Now we can execute any commands within the virtual environment.
        # This is optional and can be left out to run pip manually.
        postShellHook = ''
          # allow pip to install wheels
          unset SOURCE_DATE_EPOCH
        '';

        # Dependency for NixOS
        LD_LIBRARY_PATH = ''${pkgs.stdenv.cc.cc.lib}/lib/:${pkgs.libGL}/lib/:${pkgs.glib.out}/lib:/run/opengl-driver/lib/'';
      };
    });
}
