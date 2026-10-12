{
  description = "agentnet (NOMS 2027): atribuicao de conexoes TCP a execucoes de agentes com eBPF";

  # Mesma base do CMP223. A revisao exata fica em flake.lock (copiado para cada campanha).
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
        # Camada 1 (fixada por Nix): ferramentas de usuario, orquestracao e analise.
        # Camada 2 (do host, registrada por campanha): kernel, bpftrace, bpftool.
        packages = with pkgs; [
          bashInteractive coreutils findutils gawk gnugrep gnused gnutar gzip jq which git
          snakemake pandoc pyEnv rEnv gcc
        ];
        shellHook = ''
          echo "agentnet reproducible shell"
          echo "Nix: $(nix --version 2>/dev/null)"
          echo "Python: $(python3 --version)  R: $(R --version | head -1)"
          echo "Snakemake: $(snakemake --version)"
          echo "bpftrace (host): $(command -v bpftrace >/dev/null && bpftrace --version || echo indisponivel)"
          echo "kernel (host): $(uname -r)"
        '';
      };
    };
}
