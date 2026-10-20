{
  description = "FACT (NOMS 2027): eBPF-based attribution of TCP connections to agent executions";

  # The exact revision is in flake.lock (copied into every campaign).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      rEnv = pkgs.rWrapper.override {
        packages = with pkgs.rPackages; [ readr dplyr tidyr ggplot2 knitr rmarkdown IRkernel ];
      };
      # tool implementation of the official MCP fetch server (E5lib), from PyPI with a fixed hash
      mcpServerFetch = ps: ps.buildPythonPackage rec {
        pname = "mcp_server_fetch";
        version = "2026.7.10";
        pyproject = true;
        src = ps.fetchPypi { inherit pname version; hash = "sha256-l001nfwCrMPqmQTceSkC7MUiZBXq6+UMFq+mIxtNMrQ="; };
        build-system = [ ps.hatchling ];
        dependencies = with ps; [ httpx markdownify mcp protego pydantic readabilipy requests ];
        doCheck = false;
      };
      # mcp: E4; httpx, aiohttp, requests and the fetch server: third-party client libraries (E5lib)
      # E5node: Node.js runtime and the MCP server's npm dependencies (official TypeScript SDK),
      # fetched from workload/node/package-lock.json (fixed versions and integrity hashes)
      nodejs = pkgs.nodejs_22;
      nodeModules = pkgs.importNpmLock.buildNodeModules { npmRoot = ./workload/node; inherit nodejs; };
      pyEnv = pkgs.python3.withPackages (ps: with ps; [ jupyterlab ipykernel mcp anyio httpx aiohttp requests (mcpServerFetch ps) ]);
    in {
      devShells.${system}.default = pkgs.mkShell {
        # Layer 1 (pinned by Nix): user tools, orchestration, and analysis.
        # Layer 2 (from the host, recorded per campaign): kernel, bpftrace, bpftool.
        packages = with pkgs; [
          pyEnv bashInteractive coreutils findutils gawk gnugrep gnused gnutar gzip jq which git
          snakemake pandoc rEnv gcc fontconfig ollama curl   # ollama: local model of E7 (no paid tokens); curl: E5lib
          nodejs                                           # E5node
        ];
        # font of the figures (Times, as in the IEEEtran template): fontconfig pinned by Nix
        FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.gyre-fonts ]; };
        shellHook = ''
          # exact interpreter of the workloads (the snakemake wrapper reorders PATH)
          export FACT_PYTHON=${pyEnv}/bin/python3
          # E5node: exact Node.js and the pinned node_modules of the Node MCP server
          export FACT_NODE=${nodejs}/bin/node
          if [ -d workload/node ]; then ln -sfn ${nodeModules}/node_modules workload/node/node_modules; fi
          echo "FACT reproducible shell"
          echo "Nix: $(nix --version 2>/dev/null)"
          echo "Python: $(python3 --version)  R: $(R --version | head -1)"
          echo "Snakemake: $(snakemake --version)  Node.js: $(node --version)"
          echo "bpftrace (host): $(command -v bpftrace >/dev/null && bpftrace --version || echo unavailable)"
          echo "kernel (host): $(uname -r)"
        '';
      };
    };
}
