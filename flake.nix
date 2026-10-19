{
  description = "agentnet (NOMS 2027): eBPF-based attribution of TCP connections to agent executions";

  # The exact revision is in flake.lock (copied into every campaign).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      rEnv = pkgs.rWrapper.override {
        packages = with pkgs.rPackages; [ readr dplyr tidyr ggplot2 knitr rmarkdown IRkernel ];
      };
      pyEnv = pkgs.python3.withPackages (ps: with ps; [ jupyterlab ipykernel mcp anyio ]);  # mcp: E4
    in {
      devShells.${system}.default = pkgs.mkShell {
        # Layer 1 (pinned by Nix): user tools, orchestration, and analysis.
        # Layer 2 (from the host, recorded per campaign): kernel, bpftrace, bpftool.
        packages = with pkgs; [
          pyEnv bashInteractive coreutils findutils gawk gnugrep gnused gnutar gzip jq which git
          snakemake pandoc rEnv gcc fontconfig ollama   # ollama: local model of E7 (no paid tokens)
        ];
        # font of the figures (Times, as in the IEEEtran template): fontconfig pinned by Nix
        FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.gyre-fonts ]; };
        shellHook = ''
          # exact interpreter of the workloads (the snakemake wrapper reorders PATH)
          export AGENTNET_PYTHON=${pyEnv}/bin/python3
          echo "agentnet reproducible shell"
          echo "Nix: $(nix --version 2>/dev/null)"
          echo "Python: $(python3 --version)  R: $(R --version | head -1)"
          echo "Snakemake: $(snakemake --version)"
          echo "bpftrace (host): $(command -v bpftrace >/dev/null && bpftrace --version || echo unavailable)"
          echo "kernel (host): $(uname -r)"
        '';
      };
    };
}
