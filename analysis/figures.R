#!/usr/bin/env Rscript
#' ---
#' title: "FACT: figures of the paper"
#' output: html_document
#' ---
#'
#' Literate analysis script (knitr::spin format). It runs as a plain script,
#' `Rscript analysis/figures.R`, and can also be rendered as a notebook with
#' `Rscript -e 'rmarkdown::render("analysis/figures.R", knit_root_dir = getwd())'`.
#'
#' Inputs are the summarized results produced by `analysis/analysis.R`,
#' `analysis/score_policy.py` and `analysis/baselines.py` (one CSV per
#' experiment). Outputs are the PDF figures that the paper includes from
#' `generated/`. Every number in a figure comes from these files; nothing is
#' typed by hand.
#'
#' Usage: Rscript analysis/figures.R [analysis/output] [analysis/output/fig]

#+ setup, message=FALSE
suppressPackageStartupMessages({
  library(readr); library(dplyr); library(tidyr); library(ggplot2)
})
args   <- commandArgs(trailingOnly = TRUE)
indir  <- if (length(args) >= 1) args[1] else "analysis/output"
figdir <- if (length(args) >= 2) args[2] else file.path(indir, "fig")
dir.create(figdir, showWarnings = FALSE, recursive = TRUE)

#' One theme for every figure: IEEE column width (3.5 in), 8 pt text in the
#' font of the IEEEtran template (Times; TeX Gyre Termes is the free clone that
#' the Nix shell provides through fontconfig), framed panels, shades of gray
#' only (the paper is read in print). FACT is always the darkest series
#' (black), and every series also has its own shape or line type.
col_w   <- 3.5
fam     <- "TeX Gyre Termes"
if (!any(grepl(fam, system("fc-list : family", intern = TRUE), fixed = TRUE)))
  stop("font '", fam, "' not found: run inside `nix develop` (FONTCONFIG_FILE)")
ours    <- "black"
greys   <- c("grey78", "grey55", "grey35")
theme_paper <- function() {
  theme_bw(base_size = 8, base_family = fam) +
    theme(panel.grid.minor = element_blank(),
          panel.grid.major = element_line(colour = "grey92", linewidth = 0.3),
          panel.border = element_rect(colour = "black", linewidth = 0.4),
          strip.background = element_rect(fill = "grey92", colour = "black", linewidth = 0.4),
          strip.text = element_text(size = 7.5, colour = "black"),
          axis.text = element_text(colour = "black"),
          axis.ticks = element_line(colour = "black", linewidth = 0.3),
          legend.position = "top", legend.title = element_blank(),
          legend.key.height = unit(8, "pt"), legend.margin = margin(0, 0, 0, 0),
          legend.box.spacing = unit(2, "pt"),
          panel.spacing.x = unit(4, "pt"), panel.spacing.y = unit(4, "pt"),
          plot.margin = margin(2, 4, 2, 2))
}
save_fig <- function(g, name, h) {
  dev <- if (capabilities("cairo")) cairo_pdf else "pdf"
  ggsave(file.path(figdir, paste0(name, ".pdf")), g, width = col_w, height = h, device = dev)
  message("figure: ", file.path(figdir, paste0(name, ".pdf")))
}
pct <- function(x) paste0(round(100 * x), "%")

#' ## E1: which signal attributes which structure
#'
#' Share of connections that each resolver credits to the wrong execution
#' (I/N) or reports as ambiguous (A/N), per execution structure and fault
#' fraction p. The fused resolver is FACT's. Operation modes produced
#' identical counts and are pooled.
e1 <- read_csv(file.path(indir, "cell_summary.csv"), show_col_types = FALSE) |>
  filter(experiment == "E1", label == "confirmatory") |>
  group_by(cond, wrong_label, resolver) |>
  summarise(A = sum(A_total) / sum(N_total), I = sum(I_total) / sum(N_total), .groups = "drop") |>
  pivot_longer(c(A, I), names_to = "metric", values_to = "share") |>
  mutate(metric = factor(metric, c("I", "A"), c("Wrong", "Ambiguous")),
         p = factor(paste0("p = ", wrong_label), paste0("p = ", c(0, 0.05, 0.2))),
         resolver = factor(resolver, c("cgroup", "lineage", "context", "fused"),
                           c("Cgroup Only", "Lineage Only", "Context Only", "FACT (Fused)")))
#' Drawn as an annotated heat map (the usual NOMS form for a parameter sweep):
#' rows are resolvers, columns the execution structures, and each cell gives
#' the share in percent; FACT's row is set in bold.
e1 <- e1 |> mutate(resolver = factor(resolver, rev(levels(resolver))),
                   lab = paste0(round(100 * share)),
                   face = ifelse(resolver == "FACT (Fused)", "bold", "plain"))
g1 <- ggplot(e1, aes(cond, resolver, fill = share)) +
  geom_tile(colour = "black", linewidth = 0.25) +
  geom_text(aes(label = lab, colour = share > 0.5, fontface = face), size = 2.3, family = fam) +
  facet_grid(metric ~ p) +
  scale_fill_gradient(low = "white", high = "grey25", limits = c(0, 1), labels = pct,
                      breaks = c(0, 0.5, 1), name = "Share of Connections") +
  scale_colour_manual(values = c("black", "white"), guide = "none") +
  scale_x_discrete(expand = c(0, 0)) +
  scale_y_discrete(expand = c(0, 0), labels = c("FACT (Fused)" = expression(bold("FACT (Fused)")),
                                                 "Context Only" = "Context Only", "Lineage Only" = "Lineage Only",
                                                 "Cgroup Only" = "Cgroup Only")) +
  labs(x = "Execution Structure", y = NULL) + theme_paper() +
  theme(legend.position = "none", panel.grid.major = element_blank())
save_fig(g1, "fig_e1", 2.1)

#' ## E1: accounting decomposition
#'
#' Connections per run (of 200) credited to a wrong execution or left
#' uncredited, with mislabeled markers, and the absolute net accounting error
#' summed over executions. Context-only accounting has a net error of zero
#' even when it credits connections wrongly: opposite errors cancel.
acct <- read_csv(file.path(indir, "E1_accounting.csv"), show_col_types = FALSE) |>
  pivot_longer(matches("^(wrong|unc|net)_(context|fused)$"), names_to = c("kind", "resolver"), names_sep = "_",
               values_to = "conns") |>
  mutate(resolver = factor(resolver, c("context", "fused"), c("Context Only", "FACT")),
         p = factor(paste0("p = ", wrong_label), paste0("p = ", c(0.05, 0.2))))
bars <- acct |> filter(kind != "net") |>
  mutate(kind = factor(kind, c("wrong", "unc"), c("Credited Wrongly", "Uncredited")))
net <- acct |> filter(kind == "net") |> mutate(conns = abs(conns), kind = "|Net Error|")
g2 <- ggplot(bars, aes(cond, conns)) +
  geom_col(aes(fill = kind), position = position_dodge(width = 0.75), width = 0.7,
           colour = "black", linewidth = 0.25) +
  geom_point(data = net, aes(shape = kind), size = 1.6, colour = "black") +
  facet_grid(resolver ~ p, labeller = labeller(resolver = c("Context Only" = "Context", "FACT" = "FACT"))) +
  scale_fill_manual(values = c("grey30", "grey80")) + scale_shape_manual(values = 18) +
  labs(x = "Execution Structure", y = "Connections per Run") + theme_paper()
save_fig(g2, "fig_acct", 1.9)

#' ## E5 and E6: manual vs task-scoped binding in a shared MCP server
#'
#' Correct attribution (E5) and correct policy decisions (E6) per tool type and
#' number of concurrent sessions K.
e5 <- read_csv(file.path(indir, "E5_framework.csv"), show_col_types = FALSE) |>
  transmute(binding_mode, tool, K = execs, value = C_N, metric = "attribution")
e6 <- read_csv(file.path(indir, "E6_policy.csv"), show_col_types = FALSE) |>
  transmute(binding_mode, tool, K = execs, value = (TA + TD) / N, metric = "policy")
fw <- bind_rows(e5, e6) |>
  mutate(binding = factor(binding_mode, c("manual", "auto"),
                          c("Thread-Keyed Markers", "FACT (Task-Scoped)")),
         tool = factor(tool, c("sync", "thread", "subproc", "async"), c("Synchronous", "Threaded", "Subprocess", "Asynchronous")),
         metric = factor(metric, c("attribution", "policy"), c("Attribution", "Policy")))
g3 <- ggplot(fw, aes(factor(K), value, colour = binding, shape = binding, linetype = binding, group = binding)) +
  geom_line(linewidth = 0.6) + geom_point(size = 1.7, stroke = 0.7) +
  geom_text(data = filter(fw, binding_mode == "manual", tool == "Asynchronous"),
            aes(label = pct(value), hjust = ifelse(K == 2, -0.15, 0.5)),
            vjust = -0.8, size = 2.1, family = fam, colour = "black", show.legend = FALSE) +
  facet_grid(metric ~ tool) +
  scale_y_continuous(labels = pct, limits = c(0, 1.12), breaks = c(0, 0.5, 1), expand = c(0, 0)) +
  scale_colour_manual(values = c(greys[2], ours)) + scale_shape_manual(values = c(2, 16)) +
  scale_linetype_manual(values = c("dashed", "solid")) +
  labs(x = "Concurrent Sessions (K)", y = "Correct Outcomes") + theme_paper()
save_fig(g3, "fig_e5e6", 2.05)

#' ## Related systems vs FACT in shared workers
#'
#' Emulations of the correlation mechanisms of related systems on the same
#' logs (`analysis/baselines.py`) and AgentProvenance executed for real with
#' client-side (E5ap) and server-side (E5aps) call windows:
#' share of connections credited to the wrong execution.
bl_csv <- file.path(indir, "baselines.csv")
if (file.exists(bl_csv)) {
  bl <- read_csv(bl_csv, show_col_types = FALSE, col_types = cols(.default = "c")) |>
    mutate(across(c(N, C, A, M, I, p), as.numeric)) |>
    mutate(cell = case_when(cond == "N3" & p == 0 ~ "E1 N3",
                            cond == "E5" & K == "8" ~ paste("E5", tool), TRUE ~ NA_character_)) |>
    filter(!is.na(cell)) |>
    filter((cell == "E1 N3" & resolver %in% c("tw-nearest-500ms", "scope-latest", "fused")) |
           (cell != "E1 N3" & binding_mode == "manual" & resolver %in% c("tw-nearest-500ms", "scope-latest")) |
           (cell != "E1 N3" & binding_mode != "manual" & resolver == "fused")) |>
    group_by(cell, resolver) |> summarise(Cc = sum(C) / sum(N), I = sum(I) / sum(N), .groups = "drop")
  #' AgentProvenance executed for real next to FACT in the E5 rounds (E5ap,
  #' `analysis/agentprov_table.py`), with eight sessions, when available.
  ap_csv <- file.path(indir, "E5ap_agentprov.csv")
  if (file.exists(ap_csv)) {
    ap <- read_csv(ap_csv, show_col_types = FALSE) |> filter(system == "AgentProvenance", execs == 8) |>
      transmute(cell = paste("E5", tool), resolver = "agentprov", Cc = C / N, I = I / N)
    bl <- bind_rows(bl, ap)
  }
  #' The same with the call windows measured inside the server (E5aps).
  aps_csv <- file.path(indir, "E5aps_agentprov.csv")
  if (file.exists(aps_csv)) {
    aps <- read_csv(aps_csv, show_col_types = FALSE) |> filter(system == "AgentProvenance", execs == 8) |>
      transmute(cell = paste("E5", tool), resolver = "agentprov_srv", Cc = C / N, I = I / N)
    bl <- bind_rows(bl, aps)
  }
  #' AgentProvenance executed for real on the synthetic shared worker (E1ap, N3),
  #' with client-side operation windows (the synthetic workload has no server).
  e1ap_csv <- file.path(indir, "E1ap_agentprov.csv")
  if (file.exists(e1ap_csv)) {
    e1ap <- read_csv(e1ap_csv, show_col_types = FALSE) |> filter(system == "AgentProvenance", cond == "N3") |>
      summarise(Cc = sum(C) / sum(N), I = sum(I) / sum(N)) |> mutate(cell = "E1 N3", resolver = "agentprov")
    bl <- bind_rows(bl, e1ap)
  }
  bl <- bl |>
    mutate(mech = factor(resolver, c("tw-nearest-500ms", "scope-latest", "agentprov", "agentprov_srv", "fused"),
                         c("Time Window (Emulated)", "Latest Scope (Emulated)",
                           "AgentProvenance, Client Windows", "AgentProvenance, Server Windows", "FACT")),
           cell = factor(cell, c("E1 N3", "E5 sync", "E5 thread", "E5 subproc", "E5 async"), c("Synthetic\nShared Worker", "Synchronous", "Threaded", "Subprocess", "Asynchronous"))) |>
    select(cell, mech, Cc, I) |> complete(cell, mech)   # empty slot where a system was not run
  g4 <- ggplot(bl, aes(cell, I, fill = mech)) +
    geom_col(position = position_dodge(width = 0.86), width = 0.82, colour = "black", linewidth = 0.25) +
    geom_text(aes(y = ifelse(is.na(I), 0, I), label = ifelse(is.na(I), "", round(100 * I)), group = mech), position = position_dodge(width = 0.86),
              vjust = -0.35, size = 1.8, family = fam) +
    scale_y_continuous(labels = pct, limits = c(0, 1.12), breaks = c(0, 0.5, 1), expand = c(0, 0)) +
    scale_fill_manual(values = c(greys[1], greys[2], greys[3], "white", ours), drop = FALSE) +
    guides(fill = guide_legend(nrow = 3)) +
    labs(x = NULL, y = "Credited to the Wrong Execution") + theme_paper()
  save_fig(g4, "fig_baselines", 2.4)
} else message("baselines.csv not found: run `snakemake baselines` first")

#+ session
sessionInfo()

#+ noms-revision extra figures: fig_baselines2 (correct-attribution framing) + fig_realagents (E7, external baselines)
if (exists("bl")) {
  blc <- bl |> mutate(correct = Cc)   # correct share (C/N): ambiguous and missing are not counted as correct
  g4b <- ggplot(blc, aes(cell, correct, fill = mech)) +
    geom_col(position = position_dodge(width = 0.86), width = 0.82, colour = "black", linewidth = 0.25) +
    geom_text(aes(y = ifelse(is.na(correct), 0, correct), label = ifelse(is.na(correct), "n/a", round(100 * correct)), group = mech),
              position = position_dodge(width = 0.86), vjust = -0.3, size = 1.7, family = fam) +
    scale_y_continuous(labels = pct, limits = c(0, 1.16), breaks = c(0, 0.5, 1), expand = c(0, 0)) +
    scale_fill_manual(values = c(greys[1], greys[2], greys[3], "white", ours), drop = FALSE) +
    guides(fill = guide_legend(nrow = 3)) +
    labs(x = NULL, y = "Correctly Attributed") + theme_paper() +
    theme(legend.text = element_text(size = 6), legend.key.width = unit(7, "pt"), legend.spacing.x = unit(2, "pt"))
  save_fig(g4b, "fig_baselines2", 2.4)
}

ra_csv <- file.path(indir, "E7_attrib.csv")
if (file.exists(ra_csv)) {
  ra <- read_csv(ra_csv, show_col_types = FALSE) |>
    filter(resolver %in% c("cgroup", "lineage", "fused")) |>
    transmute(resolver, Correct = C / N, Ambiguous = A / N) |>
    mutate(resolver = recode(resolver, cgroup = "Cgroup", lineage = "Process Lineage", fused = "FACT"),
           resolver = factor(resolver, c("Cgroup", "Process Lineage", "FACT"))) |>
    pivot_longer(c(Correct, Ambiguous), names_to = "outcome", values_to = "frac") |>
    mutate(outcome = factor(outcome, c("Ambiguous", "Correct")))
  g5 <- ggplot(ra, aes(resolver, frac, fill = outcome)) +
    geom_col(width = 0.66, colour = "black", linewidth = 0.3) +
    geom_text(data = subset(ra, frac > 0.02), aes(label = pct(frac), colour = outcome),
              position = position_stack(vjust = 0.5), size = 2.1, family = fam) +
    scale_y_continuous(labels = pct, expand = c(0, 0), limits = c(0, 1.001)) +
    scale_fill_manual(values = c(Ambiguous = "grey80", Correct = ours)) +
    scale_colour_manual(values = c(Ambiguous = "black", Correct = "white"), guide = "none") +
    labs(x = NULL, y = "Real-Agent Connections") + theme_paper()
  save_fig(g5, "fig_realagents", 1.8)
}
