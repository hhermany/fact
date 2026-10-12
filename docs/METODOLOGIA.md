# Metodologia científica — agentnet / NOMS 2027 (v0.4, 12/10/2026)

Rascunho para revisão do grupo (Eder, Jéferson). A v0.4 incorpora o framework (vínculo automático no runtime, política por execução, daemon ao vivo, agente LLM local) e amarra **cada decisão de método a uma referência verificada** (lista na Seção 11). Os itens marcados **[decidir]** dependem de decisão humana. A v0.3 está no histórico do git.

## 0. Estado e regras de uso dos dados

| Etapa | Uso permitido |
|---|---|
| Smoke tests e pilotos | Validar o pipeline e estimar variabilidade. **Nunca são resultados**, e nunca entram no artigo como evidência. |
| Campanhas `confirmatory` | **Única fonte de números do artigo.** Exigem commit limpo, preflight PASS e nenhuma rodada com falha. Uma campanha com qualquer falha é preservada como registro, mas é excluída das tabelas. |

Números de smoke e piloto citados em documentos internos vêm sempre rotulados como tal.

## 1. Questão científica e contribuição

**Questão:** é possível atribuir cada conexão de rede à execução de agente que a originou, inclusive dentro de um worker compartilhado com ferramentas assíncronas, reportar explicitamente quando a atribuição não é possível e usar essa identidade para gerência (contabilidade e política), com custo aceitável?

**Contribuição (framework):**
1. sinais do kernel (lineage, cgroup) e uma identidade emitida pelo runtime, fundidos com ambiguidade explícita;
2. vínculo automático da identidade à **tarefa** (contextvars), entregue ao kernel no `connect`/fork, sem alterar o código das ferramentas;
3. contabilidade por execução ao vivo (agentnetd), com as parcelas corretas, creditadas errado e não creditadas;
4. política de saída por execução (cgroup/connect4) com a mesma identidade;
5. validação de tudo contra uma referência independente.

| RQ | Hipótese operacional |
|---|---|
| RQ1 suficiência dos sinais | Por construção: cgroup é ambíguo em N1–N3 e lineage em N2–N3. Mede-se se o sistema **reporta** A em vez de I, e a perda de captura. |
| RQ2 fusão sob contexto errado | H2a: em N0/N1, I(fused)=0 para qualquer fração p de rótulos errados. H2b: em N2/N3, I(fused)=I(context). |
| RQ3 contabilidade | O erro líquido subestima o erro de atribuição; a decomposição o expõe. |
| RQ4 custo e escala | Custo por conexão (E3/E3b), sem perda até o limite medido (E2). |
| RQ5 framework | H5a: com vínculo automático, I=0 também para ferramentas async (E5). H5b: as decisões da política seguem a identidade correta (E6). H5c: o sistema funciona com agentes LLM reais (E7). |

## 2. Técnica, objeto e escopo

- **Técnica:** medição em sistema real com workload controlado [Jain 1991, cap. 3: medição é a técnica indicada quando o sistema existe e a questão envolve o comportamento real do kernel]. A simulação entra apenas como teste de unidade (`tests/test_agentctx_sim.py`), nunca como resultado.
- **Objeto:** eventos `tcp_connect` IPv4 e decisões de `connect` (cgroup/connect4).
- **Unidade de atribuição:** execução sintética (E1–E3), sessão MCP (E4–E6) ou execução de agente LLM (E7).
- **Fora de escopo:** bytes por fluxo, IPv6, UDP, runtimes que não sejam Python (o mecanismo é geral, mas a implementação é Python).

## 3. Desenho experimental

### 3.1 Experimentos

| Exp. | RQ | Fatores (níveis) | Fixos |
|---|---|---|---|
| E1 correção | 1–3 | S ∈ {N0..N3} × p ∈ {0, 0,05, 0,2} × modo ∈ {inproc, subproc} | K=2, 100 ops/execução |
| E2 escala | 4 | S ∈ {N1, N3} × K ∈ {2..64} × taxa ∈ {pausada, máxima} | p=0 |
| E3 overhead | 4 | instrumentação ∈ {nenhuma, coletor} × marcadores ∈ {não, sim} | 20.000 connects/rodada |
| E3b ablação | 4 | coletor ∈ {nenhum, só probes, completo, otimizado} × marcadores | idem |
| E1fast | 4 | = E1, com o coletor otimizado | equivalência |
| E4 runtime real | 1 | ferramenta ∈ {sync, thread, subproc, async} × K ∈ {2,4} | marcadores manuais |
| **E5 framework** | 5 | vínculo ∈ {manual, automático} × ferramenta × K ∈ {2,4,8} | servidor MCP real |
| **E6 política** | 5 | vínculo × ferramenta × K ∈ {2,8} | classes P/R alternadas |
| **E7 agente LLM** | 5 | K=4 agentes (Ollama, temperatura 0) | vínculo automático + política |

E1, E5 e E6 são fatoriais completos, o que permite estimar efeitos e interações sem confundimento [Montgomery 2017, caps. 5–6; Jain 1991, parte IV].

### 3.2 Princípios de desenho

- **Comparação pareada.** Os quatro resolvers são aplicados offline ao mesmo log de cada rodada, de modo que as diferenças entre resolvers não vêm de execuções diferentes (bloqueio no nível da rodada [Montgomery 2017, cap. 4]).
- **Referência independente.** Cada operação recebe uma porta de destino exclusiva, sorteada antes da rodada. Os resolvers só recebem `ts, pid, tid, cgroup, ctx`, e uma checagem por AST bloqueia campos da referência. Esse é um **oráculo de teste independente da implementação** [Barr et al. 2015]: o veredito não usa nenhuma informação que o sistema avaliado possa ter corrompido. Na política (E6/E7), o veredito esperado é derivado da porta (dona) e da lista de permissões da dona.
- **Injeção de falhas controlada.** Os rótulos errados em número exato (p × ops por execução, posições sorteadas) seguem a metodologia de injeção de falhas para validar mecanismos de tolerância [Arlat et al. 1990; Hsueh, Tsai & Iyer 1997]: falhas definidas (tipo, local, momento), ativação controlada e observação do efeito. Com contagem exata, a injeção não adiciona variância de amostragem.
- **Randomização da ordem das rodadas** (semente registrada). Viés de medição pode surgir de fatores de configuração aparentemente irrelevantes [Mytkowicz et al. 2009]. Sortear a ordem impede que a condição se confunda com a posição temporal, com o aquecimento ou com a deriva.
- **Números aleatórios comuns** entre condições (mesma semente por repetição), declarados no artigo; isso reduz a variância das comparações entre condições [Jain 1991].
- **Vários boots como blocos** (E1, E3, E3b, E5, E6). O estado do sistema após o boot é um nível de variação próprio, e só repetir em vários boots o captura [Kalibera & Jones 2013; Georges et al. 2007].

### 3.3 Unidade de repetição e N: critério por experimento

**Unidade:** a rodada completa, com coletor novo, cgroups novos e serviços novos. Eventos dentro de uma rodada são dependentes, e contá-los como réplicas seria pseudo-repetição [Georges et al. 2007, que usam a invocação da VM como unidade]. As rodadas de um mesmo boot são réplicas dentro de um bloco [Kalibera & Jones 2013].

| Tipo de resultado | Experimentos | Critério de N |
|---|---|---|
| **Propriedade (zero erros esperado)** | E1, E5 (automático), E6 (automático), E7 | Limite superior exato de Clopper-Pearson para a taxa de erro [Clopper & Pearson 1934]. Com 0 erros em n casos, o limite unilateral de 95% é 1−0,05^(1/n) ≈ 3/n ("regra de três" [Hanley & Lippman-Hand 1983]). **Alvo: ≤ 1% ⇒ n ≥ 299 casos por célula.** Os casos são conexões ou decisões. Como eventos de uma rodada não são independentes, o limite é interpretado por conexão e acompanhado da verificação, rodada a rodada, de que nenhuma rodada teve erro. |
| **Desempenho (variável contínua)** | E3, E3b | Variância medida no piloto por nível (boot, rodada), e N por nível escolhido pelo método de Kalibera & Jones 2013. O alvo é a meia-largura do IC95% da mediana ≤ 5% [Hoefler & Belli 2015, regra 5]. **Mínimo de 2 boots.** |
| **Capacidade** | E2 | Varredura de K e taxa até a primeira perda. N por célula dado pela variabilidade da perda no piloto [Hoefler & Belli 2015]. |
| **Equivalência** | E1fast; agentnetd × offline | Igualdade exata célula a célula ou rodada a rodada. Uma única divergência refuta. |

Aplicação: no E5 e no E6, a menor célula (K=2, 25 ops) tem 50 casos por rodada, logo 299/50 ⇒ **6 rodadas por célula (3 por boot, 2 boots)**. Células com K maior têm mais casos e o mesmo N. No E7, o N sai do mesmo critério, aplicado ao número de decisões por rodada observado no piloto.

### 3.4 Métricas

- C/N, A/N, M/N, I/N, C/(C+I) e A_in por resolver; captura (tentadas, capturadas, perdidas, duplicadas, excluídas sem referência), sempre reportada.
- **Contabilidade:** corretas, creditadas errado, não creditadas. O erro líquido nunca é reportado sozinho.
- **Política:** TA, TD, FA (permitida indevidamente: risco de segurança), FD (negada indevidamente: perda de disponibilidade), ND (sem decisão).
- **Desempenho:** mediana e p99 da latência de `connect`, vazão, ns por execução de programa BPF (bpf_stats) e CPU do processo coletor; latência das chamadas de ferramenta (E4–E7).
- **Agente (E7):** chamadas de ferramenta, portas fora do plano (alucinação), tempo de LLM, conclusão da tarefa.

### 3.5 Plano de análise (pré-registrado)

1. **Validação:** rodadas com falha invalidam a campanha. Captura sempre reportada.
2. **Propriedades:** contagens totais com o limite de Clopper-Pearson; I=0 é testado como propriedade, sem teste de significância, porque o resultado é determinístico dado o plano [Jain 1991, cap. 2, "erros comuns"].
3. **Desempenho:** mediana por rodada, depois média das medianas com IC95% sobre rodadas, com o boot como bloco. Bootstrap por rodada como verificação [Le Boudec 2010, cap. 2]. Tamanho de efeito reportado em µs e em %, nunca só a significância [Hoefler & Belli 2015].
4. Tabelas e figuras geradas por script (R) a partir das campanhas imutáveis; nenhum número digitado à mão. O `results_meta.tex` registra a proveniência.

## 4. Controles e ambiente

- **Controlado:** workload, sementes, níveis, ordem, estado reiniciado por rodada, ausência de outras campanhas (preflight).
- **Registrado por campanha:** kernel, bpftrace, bpftool, Python, R, BTF, CPU, memória, virtualização (VMware), loadavg, NTP, commit e flake.lock [Bajpai et al. 2019; Collberg & Proebsting 2016].
- **Limitação:** VM com 8 vCPUs, sem controle de frequência. Isso é declarado; os vários boots mitigam parcialmente.

## 5. Reprodutibilidade

- **Duas camadas.** O Nix flake fixa Python, R, Snakemake, Jupyter e Ollama. Kernel, bpftrace, clang e libbpf vêm do host e são registrados.
- **Snakemake:** preflight → piloto → dimensionar → campanha → validar → relatório.
- **Cada campanha é imutável:** manifest.json, run_order, environment/, checksums SHA-256 e .tar.gz.
- **Artefato público** (código, dados e scripts) segundo as recomendações para pesquisa experimental em redes [Bajpai et al. 2019]. **[decidir: Zenodo × Git LFS; link anônimo na submissão?]**

## 6. Ameaças à validade (categorias de Wohlin et al. 2012)

- **Interna:**
  - perda de captura sob carga (medida no E2);
  - reuso de `sk` ou de PID;
  - estado residual entre rodadas (mitigado por coletor e cgroups novos);
  - interferência entre o coletor bpftrace e o programa de política, que coexistem no E6/E7.
- **De construto:**
  - "conexão" significa tentativa de `connect`;
  - uma execução sintética não é uma tarefa real (mitigado no E4–E7 com servidor MCP real e agentes LLM);
  - no E7, o comportamento do modelo é parte do workload, e não uma variável controlada.
- **Externa:**
  - um host, um kernel e uma versão do SDK MCP;
  - modelo pequeno (3B) e local;
  - implementação do vínculo apenas para Python;
  - loopback, IPv4.
- **Das conclusões:**
  - dependência entre eventos de uma rodada (tratada com a rodada como unidade);
  - números aleatórios comuns, declarados;
  - limites de Clopper-Pearson calculados por conexão sob dependência, e por isso interpretados com a verificação rodada a rodada.

## 7. Incidentes de engenharia registrados

1. **Portas na faixa efêmera** (EADDRINUSE no piloto do E2). Corrigido com portas acima de 61000 e checagem de `ip_local_port_range`.
2. **`e3_round.sh` sem bit de execução.** Corrigido no commit 43c69de.
3. **bpftrace órfão após rodada com falha.** Inflou a latência de um piloto do E4. Corrigido com trap EXIT no commit 6a27d3d.
4. **O trap propagava a falha do `kill` sob `set -e`** e invalidou a E1fast 165110Z. Corrigido no commit 0609da0; a campanha foi mantida e excluída das tabelas.

## 8. Pendências [decidir]

- Revisão do Eder: critérios de N, inclusão do E7 com modelo de 3B e semântica da política (classes P/R; ação padrão quando não há contexto).
- Repositório do artefato.

## 9. Referências metodológicas (verificadas em 12/10/2026)

- J. Arlat et al. Fault injection for dependability validation: a methodology and some applications. *IEEE TSE* 16(2), 1990.
- V. Bajpai et al. The Dagstuhl beginners guide to reproducibility for experimental networking research. *ACM SIGCOMM CCR* 49(1), 2019.
- E. T. Barr, M. Harman, P. McMinn, M. Shahbaz, S. Yoo. The oracle problem in software testing: a survey. *IEEE TSE* 41(5), 2015.
- C. J. Clopper, E. S. Pearson. The use of confidence or fiducial limits illustrated in the case of the binomial. *Biometrika* 26(4), 1934.
- C. Collberg, T. A. Proebsting. Repeatability in computer systems research. *CACM* 59(3), 2016.
- A. Georges, D. Buytaert, L. Eeckhout. Statistically rigorous Java performance evaluation. *OOPSLA* 2007.
- J. A. Hanley, A. Lippman-Hand. If nothing goes wrong, is everything all right? Interpreting zero numerators. *JAMA* 249(13), 1983.
- T. Hoefler, R. Belli. Scientific benchmarking of parallel computing systems: twelve ways to tell the masses when reporting performance results. *SC* 2015.
- M.-C. Hsueh, T. K. Tsai, R. K. Iyer. Fault injection techniques and tools. *IEEE Computer* 30(4), 1997.
- R. Jain. *The Art of Computer Systems Performance Analysis.* Wiley, 1991.
- T. Kalibera, R. Jones. Rigorous benchmarking in reasonable time. *ISMM* 2013.
- J.-Y. Le Boudec. *Performance Evaluation of Computer and Communication Systems.* EPFL Press, 2010.
- D. C. Montgomery. *Design and Analysis of Experiments*, 9th ed. Wiley, 2017.
- T. Mytkowicz, A. Diwan, M. Hauswirth, P. F. Sweeney. Producing wrong data without doing anything obviously wrong! *ASPLOS* 2009.
- C. Wohlin et al. *Experimentation in Software Engineering.* Springer, 2012.

Os números de capítulo citados acima serão conferidos nos livros antes de entrar no artigo.
