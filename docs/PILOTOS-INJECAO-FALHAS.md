# Pilotos de injeção de falhas (E5f, E6f, E6n, E7f) — 13/10/2026

Pilotos (n = 1 por célula; E7f n = 2). Não são resultados do artigo: servem para validar o protocolo
e dimensionar a campanha confirmatória, se aprovada. Commit do código: 21f34fb.

Falha injetada: uma fração exata p das chamadas de cada execução leva a identidade de outra execução
(no `_meta` do MCP, vínculo automático; em N0/N1, no marcador). Posições sorteadas com semente registrada.

| Exp. | Estrutura | p | Resultado do piloto |
|---|---|---|---|
| E5f | servidor MCP compartilhado, 4 ferramentas, K = 2 e 8 | 0,04 e 0,20 | Toda conexão com rótulo errado foi atribuída à execução errada (I = conexões com rótulo errado, em todas as 16 células) e nenhuma outra foi afetada: a falha não se propaga para chamadas seguintes. |
| E6f | idem, com política | 0,04 e 0,20 | Todas as decisões erradas vieram de chamadas com rótulo errado: 44 liberações e 88 negações indevidas para 240 chamadas com rótulo errado (55%); nenhum erro nas demais. Conexões negadas não chegam ao tcp_connect e não aparecem na atribuição. |
| E6n | N0 e N1 (árvores distintas), com política | 0,05 e 0,20 | A fusão offline marcou como ambíguas todas as conexões com rótulo errado capturadas (I = 0), mas a política no kernel, que confia no rótulo, errou em 75–80% delas (p = 0,20: 10 FA + 20 FD de 40; p = 0,05: 3 FA + 5 FD de 10). |
| E7f | 4 agentes LLM reais, política ativa | 1 de 3 chamadas por agente | As 8 chamadas com rótulo errado foram negadas (falha fechada: as listas de permissão dos agentes são disjuntas); nenhuma liberação indevida. |

Leitura: dentro de um worker compartilhado nenhuma informação do kernel contradiz o rótulo, então a falha
passa para a contabilização e para a política, mas só nas chamadas afetadas. Com árvores distintas, a linhagem
detecta a contradição offline, e a política ainda não usa essa informação: verificar a linhagem no próprio
programa de política (vetar rótulo contradito) eliminaria esses erros. É a extensão sugerida.

Incidente: a primeira tentativa de E6f/E6n/E7f (campanhas 20261013T014638Z, 014703Z, 014716Z) falhou em todas
as rodadas porque o carregador da política não compila dentro do ambiente Nix (falta bpf/libbpf.h); foi
compilado com o toolchain do host (`make -C policy`) e os pilotos foram repetidos. As campanhas com falha ficam
registradas e não são usadas.
