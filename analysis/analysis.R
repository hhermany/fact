#!/usr/bin/env Rscript
# Análise oficial: lê analysis/runs.csv (uma linha por rodada x resolver) e gera
# tabelas e figuras. Unidade de repetição = rodada; IC95% t de Student sobre rodadas.
# Uso: Rscript analysis/analysis.R analysis/runs.csv analysis/output [analysis/overhead.csv] [dir_tabelas_tex]
# As tabelas .tex vão para o artigo via \input; cada uma declara a campanha de origem.
suppressPackageStartupMessages({
  library(readr); library(dplyr); library(tidyr); library(ggplot2)
})

args <- commandArgs(trailingOnly = TRUE)
runs_csv <- if (length(args) >= 1) args[1] else "analysis/runs.csv"
outdir   <- if (length(args) >= 2) args[2] else "analysis/output"
ovh_csv  <- if (length(args) >= 3) args[3] else "analysis/overhead.csv"
texdir   <- if (length(args) >= 4) args[4] else file.path(outdir, "tex")
dir.create(texdir, showWarnings = FALSE, recursive = TRUE)
prio <- c("confirmatory", "pilot", "validation", "smoke")
pick_label <- function(labels) prio[prio %in% labels][1]
f3 <- function(x) ifelse(is.na(x), "--", formatC(x, format = "f", digits = 3))
tex_meta <- character()   # macros de proveniência para o artigo
dir.create(outdir, showWarnings = FALSE, recursive = TRUE)

ci95 <- function(x) {
  x <- x[!is.na(x)]; n <- length(x)
  if (n < 2) return(NA_real_)
  qt(0.975, n - 1) * sd(x) / sqrt(n)
}

runs <- read_csv(runs_csv, show_col_types = FALSE) |>
  mutate(C_N = C / N, A_N = A / N, M_N = M / N, I_N = I / N,
         wrong_N = credited_wrong / N, capture = captured / attempted,
         resolver = factor(resolver, levels = c("cgroup", "lineage", "context", "fused")))

# --- validação: nenhuma rodada some sem registro (todas as campanhas, inclusive as com falha)
val <- runs |> distinct(campaign_id, run_id, attempted, captured, lost, excluded_no_ref, git_dirty, label,
                        campaign_runs_failed) |>
  group_by(campaign_id, label, campaign_runs_failed) |>
  summarise(rodadas = n(), tentadas = sum(attempted), capturadas = sum(captured),
            perdidas = sum(lost), excluidas_sem_ref = sum(excluded_no_ref),
            git_dirty = any(git_dirty), .groups = "drop")
write_csv(val, file.path(outdir, "validacao_campanhas.csv"))
# regra: campanhas com qualquer rodada falha ficam fora das tabelas e figuras
excluidas <- unique(runs$campaign_id[runs$campaign_runs_failed > 0])
if (length(excluidas)) message("campanhas excluídas por rodadas falhas: ", paste(excluidas, collapse = ", "))
runs <- runs |> filter(campaign_runs_failed == 0)

# --- resumo por célula
keys <- c("experiment", "label", "cond", "wrong_label", "mode", "execs", "jitter", "resolver")
resumo <- runs |>
  group_by(across(all_of(keys))) |>
  summarise(rodadas = n(),
            across(c(C_N, A_N, M_N, I_N, wrong_N, capture),
                   list(media = ~mean(.x), ic95 = ~ci95(.x))),
            C_total = sum(C), A_total = sum(A), M_total = sum(M), I_total = sum(I), N_total = sum(N),
            .groups = "drop")
write_csv(resumo, file.path(outdir, "resumo_celulas.csv"))

# --- diferença pareada context - fused em I/N (mesma rodada, mesmo log)
pareado <- runs |>
  filter(resolver %in% c("context", "fused")) |>
  select(all_of(setdiff(keys, "resolver")), run_id, campaign_id, resolver, I_N) |>
  pivot_wider(names_from = resolver, values_from = I_N) |>
  mutate(dif = context - fused) |>
  group_by(across(all_of(setdiff(keys, "resolver")))) |>
  summarise(rodadas = n(), dif_media = mean(dif), dif_ic95 = ci95(dif), .groups = "drop")
write_csv(pareado, file.path(outdir, "pareado_context_menos_fused.csv"))

tema <- theme_bw(base_size = 10) + theme(legend.position = "bottom")

# --- figuras E1
e1 <- resumo |> filter(experiment == "E1")
if (nrow(e1) > 0) {
  for (lab in unique(e1$label)) {
    d <- e1 |> filter(label == lab)
    g <- ggplot(d, aes(wrong_label, I_N_media, colour = resolver, shape = resolver)) +
      geom_point(position = position_dodge(width = 0.02)) +
      geom_errorbar(aes(ymin = I_N_media - I_N_ic95, ymax = I_N_media + I_N_ic95),
                    width = 0.01, position = position_dodge(width = 0.02), na.rm = TRUE) +
      facet_grid(mode ~ cond) +
      labs(x = "taxa de rótulos errados p", y = "atribuições incorretas I/N",
           title = paste0("E1 (", lab, "): atribuição incorreta por estrutura")) + tema
    ggsave(file.path(outdir, paste0("E1_", lab, "_I_vs_p.pdf")), g, width = 7, height = 4)
    g2 <- g + aes(y = A_N_media) +
      geom_errorbar(aes(ymin = A_N_media - A_N_ic95, ymax = A_N_media + A_N_ic95), width = 0.01, na.rm = TRUE) +
      labs(y = "ambiguidades A/N", title = paste0("E1 (", lab, "): ambiguidade por estrutura"))
    ggsave(file.path(outdir, paste0("E1_", lab, "_A_vs_p.pdf")), g2, width = 7, height = 4)
  }
}

# --- E1: decomposição contábil por execução (RQ3) e limite de Clopper-Pearson (H2a)
if (nrow(e1) > 0) {
  labA <- pick_label(unique(e1$label))
  dA <- runs |> filter(experiment == "E1", label == labA, wrong_label > 0, resolver %in% c("context", "fused"))
  tA <- dA |> group_by(cond, wrong_label, resolver) |>
    summarise(runs = n_distinct(paste(campaign_id, run_id)), ok = mean(credited_ok), wrong = mean(credited_wrong),
              unc = mean(uncredited), net = mean(abs_net_error), .groups = "drop") |>
    pivot_wider(names_from = resolver, values_from = c(ok, wrong, unc, net)) |> arrange(wrong_label, cond)
  write_csv(tA, file.path(outdir, "E1_contabilidade.csv"))
  linhas <- sprintf("%s & %.2f & %.0f & %.0f & %.0f & %.0f & %.0f & %.0f & %.0f & %.0f \\\\", tA$cond, tA$wrong_label,
                    tA$ok_context, tA$wrong_context, tA$unc_context, tA$net_context,
                    tA$ok_fused, tA$wrong_fused, tA$unc_fused, tA$net_fused)
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
               "\\begin{tabular}{@{}lrrrrrrrrr@{}}", "\\toprule",
               " & & \\multicolumn{4}{c}{context-only} & \\multicolumn{4}{c}{fused} \\\\",
               "\\cmidrule(lr){3-6}\\cmidrule(l){7-10}",
               "Cond. & $p$ & ok & wrong & unc. & $|$net$|$ & ok & wrong & unc. & $|$net$|$ \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_acct.tex"))
  # H2a: em N0/N1 com rótulos errados, conexões rotuladas errado e I do fused
  h <- dA |> filter(cond %in% c("N0", "N1"))
  nmis <- sum(h$I[h$resolver == "context"])          # conexões com rótulo errado (context as credita errado)
  ifz <- sum(h$I[h$resolver == "fused"])
  up <- qbeta(0.95, ifz + 1, max(nmis - ifz, 1e-9))
  tex_meta <- c(tex_meta, sprintf("\\def\\EOneMislabeled{%d}", nmis), sprintf("\\def\\EOneFusedWrong{%d}", ifz),
                sprintf("\\def\\EOneFusedUp{%.2f}", 100 * up))
}

# --- figuras E2
e2 <- resumo |> filter(experiment == "E2", resolver == "fused")
if (nrow(e2) > 0) {
  for (lab in unique(e2$label)) {
    d <- e2 |> filter(label == lab) |> mutate(taxa = ifelse(jitter == 0, "máxima", "com pausa"))
    g <- ggplot(d, aes(execs, capture_media, colour = taxa)) +
      geom_line() + geom_point() +
      geom_errorbar(aes(ymin = capture_media - capture_ic95, ymax = capture_media + capture_ic95),
                    width = 0.05, na.rm = TRUE) +
      scale_x_log10(breaks = c(2, 4, 8, 16, 32, 64)) + facet_wrap(~cond) +
      labs(x = "execuções concorrentes K", y = "fração capturada",
           title = paste0("E2 (", lab, "): captura vs. concorrência")) + tema
    ggsave(file.path(outdir, paste0("E2_", lab, "_captura_vs_K.pdf")), g, width = 6, height = 3.5)
  }
}

# --- tabela LaTeX E1 (modos inproc/subproc agregados; a igualdade entre modos é checada abaixo)
if (nrow(e1) > 0) {
  lab <- pick_label(unique(e1$label))
  d <- runs |> filter(experiment == "E1", label == lab)
  modos <- d |> group_by(cond, wrong_label, resolver, mode) |> summarise(I = sum(I), A = sum(A), .groups = "drop") |>
    group_by(cond, wrong_label, resolver) |> summarise(iguais = n_distinct(I) == 1 & n_distinct(A) == 1, .groups = "drop")
  write_csv(modos, file.path(outdir, "E1_modos_iguais.csv"))
  t <- d |> group_by(cond, wrong_label, resolver) |>
    summarise(A_N = mean(A_N), I_N = mean(I_N), runs = n_distinct(run_id), .groups = "drop") |>
    pivot_wider(names_from = resolver, values_from = c(A_N, I_N))
  linhas <- sprintf("%s & %.2f & %s & %s & %s & %s & %s \\\\", t$cond, t$wrong_label,
                    f3(t$A_N_cgroup), f3(t$A_N_lineage), f3(t$I_N_context), f3(t$I_N_fused), f3(t$A_N_fused))
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
               "\\begin{tabular}{@{}lcccccc@{}}", "\\toprule",
               "Cond. & $p$ & cgroup A/N & lineage A/N & context I/N & fused I/N & fused A/N \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e1.tex"))
  tex_meta <- c(tex_meta, sprintf("\\def\\EOneLabel{%s}", lab),
                sprintf("\\def\\EOneRuns{%d}", n_distinct(paste(d$campaign_id, d$run_id))),
                sprintf("\\def\\EOneCampaigns{%s}", paste(unique(d$campaign_id), collapse = ", ")))
}

# --- tabela LaTeX E2 (escala): captura e desfechos do fused por estrutura, K e taxa
e2r <- runs |> filter(experiment == "E2")
if (nrow(e2r) > 0) {
  lab <- pick_label(unique(e2r$label))
  d <- e2r |> filter(label == lab, resolver == "fused") |>
    group_by(cond, execs, jitter) |>
    summarise(runs = n(), cap = mean(capture), cap_ic = ci95(capture), lost = sum(lost),
              C_N = mean(C_N), A_N = mean(A_N), I_N = mean(I_N), .groups = "drop") |>
    arrange(cond, jitter, execs)
  write_csv(d, file.path(outdir, "E2_escala.csv"))
  # tabela compacta: uma linha por estrutura e taxa; pior caso sobre K (detalhe completo no CSV)
  dc <- d |> group_by(cond, jitter) |>
    summarise(kmin = min(execs), kmax = max(execs), runs = sum(runs), cap_min = min(cap), lost = sum(lost),
              C_min = min(C_N), I_max = max(I_N), .groups = "drop")
  linhas <- sprintf("%s & %s & %d--%d & %d & %s & %d & %s & %s \\\\",
                    dc$cond, ifelse(dc$jitter == 0, "max", "paced"), as.integer(dc$kmin), as.integer(dc$kmax),
                    as.integer(dc$runs), f3(dc$cap_min), as.integer(dc$lost), f3(dc$C_min), f3(dc$I_max))
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão (pior caso sobre K; detalhe em E2_escala.csv)",
               "\\begin{tabular}{@{}llcrrrrr@{}}", "\\toprule",
               "Cond. & Rate & $K$ & Runs & Capt. (min) & Lost & C/N (min) & I/N (max) \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e2.tex"))
  tex_meta <- c(tex_meta, sprintf("\\def\\ETwoLabel{%s}", lab),
                sprintf("\\def\\ETwoRuns{%d}", n_distinct(paste(e2r$campaign_id, e2r$run_id)[e2r$label == lab])))
}

# --- E3: overhead
if (file.exists(ovh_csv)) {
  ov_all <- read_csv(ovh_csv, show_col_types = FALSE) |> filter(campaign_runs_failed == 0)
  ov <- ov_all |> filter(experiment == "E3")
  lab <- pick_label(unique(ov$label))
  ov <- ov |> filter(label == lab)
  base <- ov |> filter(instr == "none", markers == 0) |> summarise(p50 = mean(p50_ns), thr = mean(throughput_cps))
  e3 <- ov |> group_by(instr, markers) |>
    summarise(rodadas = n(), boots = n_distinct(boot_id),
              p50_us = mean(p50_ns) / 1000, p50_ic = ci95(p50_ns) / 1000,
              p99_us = mean(p99_ns) / 1000, p99_ic = ci95(p99_ns) / 1000,
              thr_k = mean(throughput_cps) / 1000, thr_ic = ci95(throughput_cps) / 1000,
              bpf_ns = mean(bpf_ns_per_run, na.rm = TRUE), .groups = "drop") |>
    mutate(p50_rel = 100 * (p50_us * 1000 / base$p50 - 1), thr_rel = 100 * (thr_k * 1000 / base$thr - 1))
  write_csv(e3, file.path(outdir, "E3_overhead.csv"))
  pm <- function(m, h) ifelse(is.na(h), sprintf("%.1f", m), sprintf("%.1f$\\pm$%.1f", m, h))
  linhas <- sprintf("%s & %s & %s & %s & %s & %+.1f\\%% & %s \\\\",
                    e3$instr, ifelse(e3$markers == 1, "yes", "no"),
                    pm(e3$p50_us, e3$p50_ic), pm(e3$p99_us, e3$p99_ic), pm(e3$thr_k, e3$thr_ic), e3$p50_rel,
                    ifelse(is.na(e3$bpf_ns) | is.nan(e3$bpf_ns), "--", sprintf("%.0f", e3$bpf_ns)))
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
               "\\begin{tabular}{@{}llrrrrr@{}}", "\\toprule",
               "Instr. & Markers & p50 ($\\mu$s) & p99 ($\\mu$s) & kconn/s & $\\Delta$p50 & BPF ns/run \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e3.tex"))
  tex_meta <- c(tex_meta, sprintf("\\def\\EThreeLabel{%s}", lab),
                sprintf("\\def\\EThreeRuns{%d}", nrow(ov)))
}

# --- equivalência E1fast x E1: mesmas contagens por célula e resolver (frações por rodada)
ef <- runs |> filter(experiment == "E1fast")
if (nrow(ef) > 0) ef <- ef |> filter(label == pick_label(unique(ef$label)))
if (nrow(ef) > 0) {
  ref <- runs |> filter(experiment == "E1", label == pick_label(unique(runs$label[runs$experiment == "E1"]))) |>
    group_by(cond, wrong_label, mode, resolver) |>
    summarise(C = mean(C_N), A = mean(A_N), M = mean(M_N), I = mean(I_N), .groups = "drop")
  fst <- ef |> group_by(cond, wrong_label, mode, resolver) |>
    summarise(C_f = mean(C_N), A_f = mean(A_N), M_f = mean(M_N), I_f = mean(I_N),
              capture_f = mean(capture), runs_f = n(), .groups = "drop")
  eq <- inner_join(ref, fst, by = c("cond", "wrong_label", "mode", "resolver")) |>
    mutate(igual = abs(C - C_f) < 1e-12 & abs(A - A_f) < 1e-12 & abs(M - M_f) < 1e-12 & abs(I - I_f) < 1e-12)
  write_csv(eq, file.path(outdir, "E1fast_equivalencia.csv"))
  tex_meta <- c(tex_meta, sprintf("\\def\\EOneFastCells{%d}", nrow(eq)),
                sprintf("\\def\\EOneFastEqual{%d}", sum(eq$igual)),
                sprintf("\\def\\EOneFastRuns{%d}", n_distinct(paste(ef$campaign_id, ef$run_id))))
  message("equivalência E1fast: ", sum(eq$igual), "/", nrow(eq), " células iguais")
}

# --- E4: runtime real (servidor MCP compartilhado)
e4r <- runs |> filter(experiment == "E4")
if (nrow(e4r) > 0) {
  lab <- pick_label(unique(e4r$label))
  d <- e4r |> filter(label == lab) |>
    mutate(tool = factor(tool, levels = c("sync", "thread", "subproc", "async")))
  t4 <- d |> group_by(tool, execs, resolver) |>
    summarise(C_N = mean(C_N), A_N = mean(A_N), I_N = mean(I_N), tool_ms = median(tool_ms_p50),
              runs = n_distinct(paste(campaign_id, run_id)), cap = mean(capture), .groups = "drop") |>
    pivot_wider(names_from = resolver, values_from = c(C_N, A_N, I_N)) |> arrange(tool, execs)
  write_csv(t4, file.path(outdir, "E4_mcp.csv"))
  linhas <- sprintf("%s & %d & %s & %s & %s & %s & %s & %.1f \\\\",
                    t4$tool, as.integer(t4$execs), f3(t4$A_N_lineage), f3(t4$I_N_context),
                    f3(t4$C_N_fused), f3(t4$I_N_fused), f3(t4$A_N_fused), t4$tool_ms)
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
               "\\begin{tabular}{@{}lrrrrrrr@{}}", "\\toprule",
               "Tool & $K$ & lineage A/N & context I/N & fused C/N & fused I/N & fused A/N & ms/call \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e4.tex"))
  tex_meta <- c(tex_meta, sprintf("\\def\\EFourLabel{%s}", lab),
                sprintf("\\def\\EFourRuns{%d}", n_distinct(paste(d$campaign_id, d$run_id))),
                sprintf("\\def\\EFourMCP{%s}", unique(na.omit(d$mcp_version))[1]))
}

# --- E5: framework (vínculo automático por tarefa) vs. marcadores manuais, servidor MCP real
e5r <- runs |> filter(experiment == "E5")
if (nrow(e5r) > 0) {
  lab5 <- pick_label(unique(e5r$label))
  d5 <- e5r |> filter(label == lab5, resolver == "fused") |>
    mutate(tool = factor(tool, levels = c("sync", "thread", "subproc", "async")))
  # limite superior unilateral 95% (Clopper-Pearson) da taxa de erro por conexão
  cp_up <- function(x, n) ifelse(n > 0, qbeta(0.95, x + 1, pmax(n - x, 1e-9)), NA)
  t5 <- d5 |> group_by(binding_mode, tool, execs) |>
    summarise(runs = n_distinct(paste(campaign_id, run_id)), boots = n_distinct(boot_id),
              N = sum(N), C = sum(C), I = sum(I), A = sum(A), M = sum(M),
              tool_ms = median(tool_ms_p50), .groups = "drop") |>
    mutate(C_N = C / N, I_N = I / N, I_up = cp_up(I, N))
  write_csv(t5, file.path(outdir, "E5_framework.csv"))
  w5 <- t5 |> select(binding_mode, tool, execs, C_N, I_N, I_up, tool_ms, N) |>
    pivot_wider(names_from = binding_mode, values_from = c(C_N, I_N, I_up, tool_ms, N)) |> arrange(tool, execs)
  pct <- function(x) ifelse(is.na(x), "--", sprintf("%.1f", 100 * x))
  linhas <- sprintf("%s & %d & %s & %s & %s & %s & %s & %.1f & %.1f \\\\",
                    w5$tool, as.integer(w5$execs), pct(w5$C_N_manual), pct(w5$I_N_manual),
                    pct(w5$C_N_auto), pct(w5$I_N_auto), pct(w5$I_up_auto), w5$tool_ms_manual, w5$tool_ms_auto)
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
               "\\begin{tabular}{@{}lrrrrrrrr@{}}", "\\toprule",
               " & & \\multicolumn{2}{c}{manual (\\%)} & \\multicolumn{3}{c}{automatic (\\%)} & \\multicolumn{2}{c}{ms/call} \\\\",
               "\\cmidrule(lr){3-4}\\cmidrule(lr){5-7}\\cmidrule(l){8-9}",
               "Tool & $K$ & C/N & I/N & C/N & I/N & I/N$\\le$ & man. & auto \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e5.tex"))
  tex_meta <- c(tex_meta, sprintf("\\def\\EFiveLabel{%s}", lab5),
                sprintf("\\def\\EFiveRuns{%d}", n_distinct(paste(d5$campaign_id, d5$run_id))),
                sprintf("\\def\\EFiveConnAuto{%d}", sum(t5$N[t5$binding_mode == "auto"])),
                sprintf("\\def\\EFiveWrongAuto{%d}", sum(t5$I[t5$binding_mode == "auto"])))
}

# --- E6: política por execução (decisões vs. referência)
e6r <- runs |> filter(experiment == "E6", resolver == "fused")
if (nrow(e6r) > 0) {
  lab6 <- pick_label(unique(e6r$label))
  cp_up6 <- function(x, n) ifelse(n > 0, qbeta(0.95, x + 1, pmax(n - x, 1e-9)), NA)
  t6 <- e6r |> filter(label == lab6) |>
    mutate(tool = factor(tool, levels = c("sync", "thread", "subproc", "async"))) |>
    group_by(binding_mode, tool, execs) |>
    summarise(runs = n(), N = sum(pol_N), TA = sum(pol_TA), TD = sum(pol_TD), FA = sum(pol_FA),
              FD = sum(pol_FD), ND = sum(pol_ND), .groups = "drop") |>
    mutate(ok = (TA + TD) / N, FA_N = FA / N, FD_N = FD / N, err_up = cp_up6(FA + FD + ND, N))
  write_csv(t6, file.path(outdir, "E6_policy.csv"))
  w6 <- t6 |> select(binding_mode, tool, execs, ok, FA_N, FD_N, err_up) |>
    pivot_wider(names_from = binding_mode, values_from = c(ok, FA_N, FD_N, err_up)) |> arrange(tool, execs)
  pc <- function(x) ifelse(is.na(x), "--", sprintf("%.1f", 100 * x))
  linhas <- sprintf("%s & %d & %s & %s & %s & %s & %s & %s & %s \\\\", w6$tool, as.integer(w6$execs),
                    pc(w6$ok_manual), pc(w6$FA_N_manual), pc(w6$FD_N_manual),
                    pc(w6$ok_auto), pc(w6$FA_N_auto), pc(w6$FD_N_auto), pc(w6$err_up_auto))
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
               "\\begin{tabular}{@{}lrrrrrrrr@{}}", "\\toprule",
               " & & \\multicolumn{3}{c}{manual (\\%)} & \\multicolumn{4}{c}{automatic (\\%)} \\\\",
               "\\cmidrule(lr){3-5}\\cmidrule(l){6-9}",
               "Tool & $K$ & correct & FA & FD & correct & FA & FD & err$\\le$ \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e6.tex"))
  tex_meta <- c(tex_meta, sprintf("\\def\\ESixLabel{%s}", lab6), sprintf("\\def\\ESixRuns{%d}", sum(t6$runs)),
                sprintf("\\def\\ESixDecAuto{%d}", sum(t6$N[t6$binding_mode == "auto"])))
}

# --- E7: agentes LLM reais (atribuição por resolvedor + política)
e7r <- runs |> filter(experiment == "E7")
if (nrow(e7r) > 0) {
  lab7 <- pick_label(unique(e7r$label))
  d7 <- e7r |> filter(label == lab7)
  cp7 <- function(x, n) ifelse(n > 0, qbeta(0.95, x + 1, pmax(n - x, 1e-9)), NA)
  t7 <- d7 |> group_by(resolver) |>
    summarise(runs = n_distinct(paste(campaign_id, run_id)), N = sum(N), C = sum(C), A = sum(A),
              M = sum(M), I = sum(I), .groups = "drop") |>
    mutate(C_N = C / N, A_N = A / N, M_N = M / N, I_N = I / N, I_up = cp7(I, N))
  p7 <- d7 |> filter(resolver == "fused") |>
    summarise(runs = n(), N = sum(pol_N), TA = sum(pol_TA), TD = sum(pol_TD), FA = sum(pol_FA),
              FD = sum(pol_FD), ND = sum(pol_ND), tool_ms = median(tool_ms_p50, na.rm = TRUE))
  write_csv(t7, file.path(outdir, "E7_attrib.csv")); write_csv(p7, file.path(outdir, "E7_policy.csv"))
  linhas <- sprintf("%s & %d & %.3f & %.3f & %.3f & %.3f \\\\", t7$resolver, t7$N, t7$C_N, t7$A_N, t7$M_N, t7$I_N)
  writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
               "\\begin{tabular}{@{}lrrrrr@{}}", "\\toprule",
               "Resolver & N & C/N & A/N & M/N & I/N \\\\", "\\midrule",
               linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e7.tex"))
  fz <- t7[t7$resolver == "fused", ]
  tex_meta <- c(tex_meta, sprintf("\\def\\ESevenLabel{%s}", lab7), sprintf("\\def\\ESevenRuns{%d}", p7$runs),
                sprintf("\\def\\ESevenConn{%d}", fz$N), sprintf("\\def\\ESevenWrong{%d}", fz$I),
                sprintf("\\def\\ESevenDec{%d}", p7$N),
                sprintf("\\def\\ESevenDecOK{%d}", p7$TA + p7$TD), sprintf("\\def\\ESevenFA{%d}", p7$FA),
                sprintf("\\def\\ESevenFD{%d}", p7$FD), sprintf("\\def\\ESevenND{%d}", p7$ND),
                sprintf("\\def\\ESevenToolMs{%.0f}", p7$tool_ms))
}

# --- E3b: decomposição do custo (ablação de variantes do coletor)
if (file.exists(ovh_csv)) {
  ob <- read_csv(ovh_csv, show_col_types = FALSE) |> filter(campaign_runs_failed == 0, experiment == "E3b")
  if (nrow(ob) > 0) {
    labb <- pick_label(unique(ob$label))
    ob <- ob |> filter(label == labb)
    baseb <- ob |> filter(instr == "none", markers == 0) |> summarise(p50 = mean(p50_ns))
    e3b <- ob |> mutate(instr = factor(instr, levels = c("none", "count", "collector", "fast"))) |>
      group_by(instr, markers) |>
      summarise(rodadas = n(), boots = n_distinct(boot_id),
                p50_us = mean(p50_ns) / 1000, p50_ic = ci95(p50_ns) / 1000,
                p99_us = mean(p99_ns) / 1000, thr_k = mean(throughput_cps) / 1000,
                bpf_ns = mean(bpf_ns_per_run, na.rm = TRUE), .groups = "drop") |>
      mutate(add_us = p50_us - baseb$p50 / 1000, rel = 100 * (p50_us * 1000 / baseb$p50 - 1)) |>
      arrange(markers, instr)
    write_csv(e3b, file.path(outdir, "E3b_ablacao.csv"))
    nomes <- c(none = "none", count = "probes only", collector = "full", fast = "optimized")
    linhas <- sprintf("%s & %s & %.1f$\\pm$%.1f & %.1f & %+.1f & %+.1f\\%% & %s \\\\",
                      nomes[as.character(e3b$instr)], ifelse(e3b$markers == 1, "yes", "no"),
                      e3b$p50_us, ifelse(is.na(e3b$p50_ic), 0, e3b$p50_ic), e3b$p99_us, e3b$add_us, e3b$rel,
                      ifelse(is.na(e3b$bpf_ns) | is.nan(e3b$bpf_ns), "--", sprintf("%.0f", e3b$bpf_ns)))
    writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
                 "\\begin{tabular}{@{}llrrrrr@{}}", "\\toprule",
                 "Collector & Markers & p50 ($\\mu$s) & p99 ($\\mu$s) & $+\\mu$s & $\\Delta$p50 & BPF ns/run \\\\", "\\midrule",
                 linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e3b.tex"))
    tex_meta <- c(tex_meta, sprintf("\\def\\EThreeBLabel{%s}", labb), sprintf("\\def\\EThreeBRuns{%d}", nrow(ob)))
  }
}

# --- E2b: capacidade do coletor
cap_csv <- "analysis/capacity.csv"
if (file.exists(cap_csv)) {
  cb <- read_csv(cap_csv, show_col_types = FALSE) |> filter(campaign_runs_failed == 0)
  if (nrow(cb) > 0) {
    labc <- pick_label(unique(cb$label))
    tcb <- cb |> filter(label == labc) |> group_by(collector, par) |>
      summarise(runs = n(), rate_k = mean(agg_rate_cps) / 1000, rate_ic = ci95(agg_rate_cps) / 1000,
                cap = mean(capture), cap_min = min(capture), lost = sum(lost_reported), .groups = "drop") |>
      arrange(collector, par)
    write_csv(tcb, file.path(outdir, "E2b_capacidade.csv"))
    nm <- c("agentnet.bt" = "full", "agentnet-fast.bt" = "optimized")
    linhas <- sprintf("%s & %d & %.1f$\\pm$%.1f & %.4f & %.4f & %d \\\\", nm[tcb$collector], as.integer(tcb$par),
                      tcb$rate_k, ifelse(is.na(tcb$rate_ic), 0, tcb$rate_ic), tcb$cap, tcb$cap_min, as.integer(tcb$lost))
    writeLines(c("% gerado por analysis/analysis.R — não editar à mão",
                 "\\begin{tabular}{@{}lrrrrr@{}}", "\\toprule",
                 "Collector & $P$ & kconn/s & capture & min. & lost \\\\", "\\midrule",
                 linhas, "\\bottomrule", "\\end{tabular}"), file.path(texdir, "tab_e2b.tex"))
    tex_meta <- c(tex_meta, sprintf("\\def\\ETwoBLabel{%s}", labc), sprintf("\\def\\ETwoBRuns{%d}", sum(tcb$runs)))
  }
}

eqf <- file.path(outdir, "agentnetd_equiv.json")
if (file.exists(eqf)) {
  eqt <- paste(readLines(eqf), collapse = " ")   # JSON simples gerado por tests/test_agentnetd_equiv.py
  num <- function(k) as.integer(sub(paste0('.*"', k, '": *([0-9]+).*'), "\\1", eqt))
  tex_meta <- c(tex_meta, sprintf("\\def\\AgentnetdRuns{%d}", num("runs")),
                sprintf("\\def\\AgentnetdEqual{%d}", num("equivalent")))
}

# --- Experimentos adicionais: placa de rede real (E5net, E6net, E3net), modelos maiores
# com GPU em outra máquina (E7m) e AgentProvenance executado ao lado do agentnet (E5ap)
cpu <- function(x, n) ifelse(n > 0, qbeta(0.95, x + 1, pmax(n - x, 1e-9)), NA)
e5n <- runs |> filter(experiment == "E5net", resolver == "fused")
if (nrow(e5n) > 0) {
  lab5n <- pick_label(unique(e5n$label))
  t5n <- e5n |> filter(label == lab5n) |> group_by(binding_mode, tool, execs) |>
    summarise(runs = n(), boots = n_distinct(boot_id), N = sum(N), C = sum(C), I = sum(I), A = sum(A), M = sum(M),
              captured = sum(captured), attempted = sum(attempted), tool_ms = median(tool_ms_p50), .groups = "drop") |>
    mutate(C_N = C / N, I_N = I / N, I_up = cpu(I, N))
  write_csv(t5n, file.path(outdir, "E5net_framework.csv"))
  lo <- runs |> filter(experiment == "E5", resolver == "fused", label == pick_label(unique(e5r$label))) |>
    group_by(binding_mode, tool, execs) |> summarise(C_N_lo = sum(C) / sum(N), .groups = "drop")
  dif <- t5n |> inner_join(lo, by = c("binding_mode", "tool", "execs"))
  au <- t5n |> filter(binding_mode == "auto")
  ma <- t5n |> filter(binding_mode == "manual", tool == "async")
  tex_meta <- c(tex_meta, sprintf("\\def\\EFiveNetLabel{%s}", lab5n), sprintf("\\def\\EFiveNetRuns{%d}", sum(t5n$runs)),
                sprintf("\\def\\EFiveNetConnAuto{%d}", sum(au$N)), sprintf("\\def\\EFiveNetWrongAuto{%d}", sum(au$I)),
                sprintf("\\def\\EFiveNetCapture{%d}", sum(t5n$captured)), sprintf("\\def\\EFiveNetAttempted{%d}", sum(t5n$attempted)),
                sprintf("\\def\\EFiveNetAsyncManMin{%.0f}", 100 * min(ma$C_N)), sprintf("\\def\\EFiveNetAsyncManMax{%.0f}", 100 * max(ma$C_N)),
                sprintf("\\def\\EFiveNetMaxDiff{%.0f}", 100 * max(abs(dif$C_N - dif$C_N_lo))))
}
e6n <- runs |> filter(experiment == "E6net", resolver == "fused")
if (nrow(e6n) > 0) {
  lab6n <- pick_label(unique(e6n$label))
  t6n <- e6n |> filter(label == lab6n) |> group_by(binding_mode, tool, execs) |>
    summarise(runs = n(), N = sum(pol_N), TA = sum(pol_TA), TD = sum(pol_TD), FA = sum(pol_FA),
              FD = sum(pol_FD), ND = sum(pol_ND), .groups = "drop") |> mutate(ok = (TA + TD) / N)
  write_csv(t6n, file.path(outdir, "E6net_policy.csv"))
  au <- t6n |> filter(binding_mode == "auto")
  tex_meta <- c(tex_meta, sprintf("\\def\\ESixNetLabel{%s}", lab6n), sprintf("\\def\\ESixNetRuns{%d}", sum(t6n$runs)),
                sprintf("\\def\\ESixNetDecAuto{%d}", sum(au$N)),
                sprintf("\\def\\ESixNetErrAuto{%d}", sum(au$FA + au$FD + au$ND)))
}
e7m <- runs |> filter(experiment == "E7m", resolver == "fused")
if (nrow(e7m) > 0) {
  lab7m <- pick_label(unique(e7m$label))
  t7m <- e7m |> filter(label == lab7m) |> group_by(model, execs) |>
    summarise(runs = n(), boots = n_distinct(boot_id), N = sum(N), C = sum(C), I = sum(I), A = sum(A), M = sum(M),
              pN = sum(pol_N), TA = sum(pol_TA), TD = sum(pol_TD), FA = sum(pol_FA), FD = sum(pol_FD), ND = sum(pol_ND),
              tool_ms = median(tool_ms_p50, na.rm = TRUE), .groups = "drop")
  write_csv(t7m, file.path(outdir, "E7m_agents.csv"))
  tex_meta <- c(tex_meta, sprintf("\\def\\ESevenMLabel{%s}", lab7m), sprintf("\\def\\ESevenMRuns{%d}", sum(t7m$runs)),
                sprintf("\\def\\ESevenMConn{%d}", sum(t7m$N)), sprintf("\\def\\ESevenMWrong{%d}", sum(t7m$I)),
                sprintf("\\def\\ESevenMAmb{%d}", sum(t7m$A + t7m$M)),
                sprintf("\\def\\ESevenMDec{%d}", sum(t7m$pN)), sprintf("\\def\\ESevenMDecOK{%d}", sum(t7m$TA + t7m$TD)),
                sprintf("\\def\\ESevenMFA{%d}", sum(t7m$FA)), sprintf("\\def\\ESevenMFD{%d}", sum(t7m$FD)),
                sprintf("\\def\\ESevenMND{%d}", sum(t7m$ND)),
                sprintf("\\def\\ESevenMToolMs{%.0f}", median(e7m$tool_ms_p50[e7m$label == lab7m], na.rm = TRUE)))
}
e7c <- runs |> filter(experiment == "E7c", resolver == "fused")
if (nrow(e7c) > 0) {
  lab7c <- pick_label(unique(e7c$label))
  t7c <- e7c |> filter(label == lab7c) |> group_by(model, execs) |>
    summarise(runs = n(), boots = n_distinct(boot_id), N = sum(N), C = sum(C), I = sum(I), A = sum(A), M = sum(M),
              pN = sum(pol_N), TA = sum(pol_TA), TD = sum(pol_TD), FA = sum(pol_FA), FD = sum(pol_FD), ND = sum(pol_ND),
              tool_ms = median(tool_ms_p50, na.rm = TRUE), .groups = "drop")
  write_csv(t7c, file.path(outdir, "E7c_agents.csv"))
  tex_meta <- c(tex_meta, sprintf("\\def\\ESevenCLabel{%s}", lab7c), sprintf("\\def\\ESevenCRuns{%d}", sum(t7c$runs)),
                sprintf("\\def\\ESevenCConn{%d}", sum(t7c$N)), sprintf("\\def\\ESevenCWrong{%d}", sum(t7c$I)),
                sprintf("\\def\\ESevenCAmb{%d}", sum(t7c$A + t7c$M)),
                sprintf("\\def\\ESevenCDec{%d}", sum(t7c$pN)), sprintf("\\def\\ESevenCDecOK{%d}", sum(t7c$TA + t7c$TD)))
  tkf <- file.path(outdir, "E7c_tokens.csv")
  if (file.exists(tkf)) {
    tk <- read_csv(tkf, show_col_types = FALSE)
    tex_meta <- c(tex_meta, sprintf("\\def\\ESevenCUSD{%.2f}", sum(tk$usd)),
                  sprintf("\\def\\ESevenCInTok{%.0f}", sum(tk$input_tokens) / sum(tk$agents)),
                  sprintf("\\def\\ESevenCOutTok{%.0f}", sum(tk$output_tokens) / sum(tk$agents)))
  }
}
if (file.exists(ovh_csv)) {
  o3n <- read_csv(ovh_csv, show_col_types = FALSE) |> filter(campaign_runs_failed == 0, experiment == "E3net")
  if (nrow(o3n) > 0) {
    lab3n <- pick_label(unique(o3n$label))
    t3n <- o3n |> filter(label == lab3n) |> group_by(instr, markers) |>
      summarise(runs = n(), boots = n_distinct(boot_id), p50_us = mean(p50_ns) / 1000, p50_ic = ci95(p50_ns) / 1000,
                p99_us = mean(p99_ns) / 1000, thr_k = mean(throughput_cps) / 1000, .groups = "drop")
    write_csv(t3n, file.path(outdir, "E3net_overhead.csv"))
    b0 <- t3n$p50_us[t3n$instr == "none" & t3n$markers == 0]; c0 <- t3n$p50_us[t3n$instr == "collector" & t3n$markers == 0]
    b1 <- t3n$p50_us[t3n$instr == "none" & t3n$markers == 1]; c1 <- t3n$p50_us[t3n$instr == "collector" & t3n$markers == 1]
    tex_meta <- c(tex_meta, sprintf("\\def\\EThreeNetLabel{%s}", lab3n), sprintf("\\def\\EThreeNetRuns{%d}", sum(t3n$runs)),
                  sprintf("\\def\\EThreeNetBase{%.0f}", b0), sprintf("\\def\\EThreeNetAdd{%.1f}", c0 - b0),
                  sprintf("\\def\\EThreeNetAddMk{%.1f}", c1 - b0), sprintf("\\def\\EThreeNetRel{%.0f}", 100 * (c0 / b0 - 1)))
  }
}
apf <- file.path(outdir, "E5ap_agentprov.csv")
if (file.exists(apf)) {
  ap <- read_csv(apf, show_col_types = FALSE)
  apa <- ap |> filter(system == "AgentProvenance"); ann <- ap |> filter(system == "agentnet")
  hi <- apa |> filter(tool != "subproc", execs >= 4); sp <- apa |> filter(tool == "subproc")
  tex_meta <- c(tex_meta, sprintf("\\def\\APRuns{%d}", sum(apa$runs)), sprintf("\\def\\APConn{%d}", sum(apa$N)),
                sprintf("\\def\\APWrongMin{%.0f}", 100 * min(hi$I_N)), sprintf("\\def\\APWrongMax{%.0f}", 100 * max(hi$I_N)),
                sprintf("\\def\\APWrongTwoMin{%.0f}", 100 * min(apa$I_N[apa$tool != "subproc" & apa$execs == 2])),
                sprintf("\\def\\APWrongTwoMax{%.0f}", 100 * max(apa$I_N[apa$tool != "subproc" & apa$execs == 2])),
                sprintf("\\def\\APSubMin{%.0f}", 100 * min(sp$I_N)), sprintf("\\def\\APSubMax{%.0f}", 100 * max(sp$I_N)),
                sprintf("\\def\\APAgentnetWrong{%d}", sum(ann$I)), sprintf("\\def\\APAgentnetConn{%d}", sum(ann$N)))
}

labs_exp <- c(E1 = if (exists("e1") && nrow(e1) > 0) pick_label(unique(e1$label)) else NA,
              E2 = if (nrow(e2r) > 0) pick_label(unique(e2r$label)) else NA,
              E3 = if (file.exists(ovh_csv)) pick_label(unique(read_csv(ovh_csv, show_col_types = FALSE)$label)) else NA,
              E1fast = if (nrow(ef) > 0) pick_label(unique(ef$label)) else NA,
              E3b = if (exists("labb")) labb else NA,
              E4 = if (nrow(e4r) > 0) pick_label(unique(e4r$label)) else NA,
              E5 = if (nrow(e5r) > 0) pick_label(unique(e5r$label)) else NA,
              E6 = if (nrow(e6r) > 0) pick_label(unique(e6r$label)) else NA,
              E7 = if (nrow(e7r) > 0) pick_label(unique(e7r$label)) else NA,
              E2b = if (exists("labc")) labc else NA,
              E5net = if (exists("lab5n")) lab5n else NA, E6net = if (exists("lab6n")) lab6n else NA,
              E7m = if (exists("lab7m")) lab7m else NA, E7c = if (exists("lab7c")) lab7c else NA, E3net = if (exists("lab3n")) lab3n else NA)
labs_exp <- labs_exp[!is.na(labs_exp)]
nao_conf <- labs_exp[labs_exp != "confirmatory"]
banner <- if (length(nao_conf) == 0) "\\def\\ResultsBanner{}" else
  sprintf("\\def\\ResultsBanner{\\noindent\\fbox{\\parbox{0.96\\columnwidth}{\\textcolor{red}{\\textbf{PRELIMINARY DATA:} %s --- regenerate from confirmatory campaigns before submission.}}}\\par\\medskip}",
          paste(sprintf("%s from %s campaign", names(nao_conf), nao_conf), collapse = "; "))
tex_meta <- c(tex_meta, banner)
writeLines(c("% gerado por analysis/analysis.R — proveniência dos números do artigo", tex_meta),
           file.path(texdir, "results_meta.tex"))
writeLines(capture.output(sessionInfo()), file.path(outdir, "sessionInfo.txt"))
cat("análise concluída:", nrow(runs) / 4, "rodadas;", nrow(resumo), "células ->", outdir, "\n")
