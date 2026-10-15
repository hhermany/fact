#!/usr/bin/env Rscript
#' ---
#' title: "agentnet: figures of the paper"
#' output: html_document
#' ---
#'
#' Literate analysis script (knitr::spin format). It runs as a plain script,
#' `Rscript analysis/figures.R`, and can also be rendered as a notebook with
#' `Rscript -e 'rmarkdown::render("analysis/figures.R", knit_root_dir = getwd())'`.
#'
#' Inputs are the summarized results produced by `analysis/analysis.R` and
#' `analysis/baselines.py` (one CSV per experiment, tidy enough to plot).
#' Outputs are the PDF figures that the paper includes from `generated/`.
#' Every number in a figure comes from these files; nothing is typed by hand.
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

#' One theme for every figure: IEEE column width (3.5 in), 8 pt text,
#' recessive grid. Colors are a validated categorical palette (blue, orange,
#' aqua, yellow); every series also has its own shape or line type, so the
#' figures stay readable in grayscale.
col_w <- 3.5
pal   <- c("#2a78d6", "#eb6834", "#1baf7a", "#eda100")
theme_paper <- function() {
  theme_minimal(base_size = 8) +
    theme(panel.grid.minor = element_blank(),
          panel.grid.major = element_line(colour = "grey90", linewidth = 0.3),
          strip.text = element_text(size = 7.5, face = "bold"),
          legend.position = "top", legend.title = element_blank(),
          legend.key.height = unit(8, "pt"), legend.margin = margin(0, 0, 0, 0),
          panel.spacing.x = unit(6, "pt"), panel.spacing.y = unit(9, "pt"), plot.margin = margin(2, 4, 2, 2))
}
save_fig <- function(g, name, h) {
  dev <- if (capabilities("cairo")) cairo_pdf else "pdf"
  ggsave(file.path(figdir, paste0(name, ".pdf")), g, width = col_w, height = h, device = dev)
  message("figure: ", file.path(figdir, paste0(name, ".pdf")))
}
pct <- function(x) paste0(round(100 * x), "%")

#' ## E1: which signal attributes which structure
#'
#' Share of connections that each resolver reports as ambiguous (A/N) or
#' credits to the wrong execution (I/N), per execution structure and fault
#' fraction p. Operation modes produced identical counts and are pooled.
e1 <- read_csv(file.path(indir, "resumo_celulas.csv"), show_col_types = FALSE) |>
  filter(experiment == "E1", label == "confirmatory") |>
  group_by(cond, wrong_label, resolver) |>
  summarise(A = sum(A_total) / sum(N_total), I = sum(I_total) / sum(N_total), .groups = "drop") |>
  pivot_longer(c(A, I), names_to = "metric", values_to = "share") |>
  mutate(metric = factor(metric, c("I", "A"), c("wrong", "ambiguous")),
         p = factor(paste0("p = ", wrong_label), paste0("p = ", c(0, 0.05, 0.2))),
         resolver = factor(resolver, c("cgroup", "lineage", "context", "fused"),
                           c("cgroup only", "lineage only", "context only", "fused")))
g1 <- ggplot(e1, aes(cond, share, colour = resolver, shape = resolver)) +
  geom_point(position = position_dodge(width = 0.6), size = 1.8, stroke = 0.6) +
  facet_grid(metric ~ p) +
  scale_y_continuous(labels = pct, limits = c(0, 1), breaks = c(0, 0.2, 1)) +
  scale_colour_manual(values = pal) + scale_shape_manual(values = c(16, 17, 15, 4)) +
  labs(x = "execution structure", y = "share of connections") + theme_paper()
save_fig(g1, "fig_e1", 2.25)

#' ## E1: accounting decomposition
#'
#' Connections per run (of 200) credited to a wrong execution or left
#' uncredited, with mislabeled markers, and the absolute net accounting error
#' summed over executions. Context-only accounting has a net error of zero
#' even when it credits connections wrongly: opposite errors cancel.
acct <- read_csv(file.path(indir, "E1_contabilidade.csv"), show_col_types = FALSE) |>
  pivot_longer(matches("^(wrong|unc|net)_(context|fused)$"), names_to = c("kind", "resolver"), names_sep = "_",
               values_to = "conns") |>
  mutate(resolver = factor(resolver, c("context", "fused"), c("context", "fused")),
         p = factor(paste0("p = ", wrong_label), paste0("p = ", c(0.05, 0.2))))
bars <- acct |> filter(kind != "net") |>
  mutate(kind = factor(kind, c("wrong", "unc"), c("credited wrongly", "uncredited")))
net <- acct |> filter(kind == "net") |> mutate(conns = abs(conns), kind = "|net error|")
g2 <- ggplot(bars, aes(cond, conns)) +
  geom_col(aes(fill = kind), position = position_dodge(width = 0.75), width = 0.7,
           colour = "white", linewidth = 0.3) +
  geom_point(data = net, aes(shape = kind), size = 1.8, colour = "black") +
  facet_grid(resolver ~ p) +
  scale_fill_manual(values = c(pal[2], "grey65")) + scale_shape_manual(values = 18) +
  labs(x = "execution structure", y = "connections per run") + theme_paper()
save_fig(g2, "fig_acct", 1.95)

#' ## E5 and E6: manual vs task-scoped binding in a shared MCP server
#'
#' Correct attribution (E5) and correct policy decisions (E6) per tool type and
#' number of concurrent sessions K.
e5 <- read_csv(file.path(indir, "E5_framework.csv"), show_col_types = FALSE) |>
  transmute(binding_mode, tool, K = execs, value = C_N, metric = "attribution")
e6 <- read_csv(file.path(indir, "E6_policy.csv"), show_col_types = FALSE) |>
  transmute(binding_mode, tool, K = execs, value = (TA + TD) / N, metric = "policy")
fw <- bind_rows(e5, e6) |>
  mutate(binding = factor(binding_mode, c("manual", "auto"), c("thread-keyed markers", "task-scoped (agentnet)")),
         tool = factor(tool, c("sync", "thread", "subproc", "async")),
         metric = factor(metric, c("attribution", "policy"), c("attribution", "policy")))
g3 <- ggplot(fw, aes(K, value, colour = binding, shape = binding, linetype = binding)) +
  geom_line(linewidth = 0.6) + geom_point(size = 1.8) +
  facet_grid(metric ~ tool) +
  scale_x_continuous(breaks = c(2, 4, 8), trans = "log2") +
  scale_y_continuous(labels = pct, limits = c(0, 1), breaks = c(0, 0.5, 1)) +
  scale_colour_manual(values = pal[c(2, 1)]) + scale_shape_manual(values = c(17, 16)) +
  labs(x = "concurrent sessions K", y = "correct") + theme_paper()
save_fig(g3, "fig_e5e6", 2.05)

#' ## Related mechanisms vs agentnet in shared workers
#'
#' Emulations of the correlation mechanisms of related systems on the same
#' logs (`analysis/baselines.py`): share of connections credited to the wrong
#' execution. The rows and resolvers follow `analysis/baselines_table.py`.
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
    group_by(cell, resolver) |> summarise(I = sum(I) / sum(N), .groups = "drop") |>
    mutate(mech = factor(resolver, c("tw-nearest-500ms", "scope-latest", "fused"),
                         c("time window (AgentSight-style)", "latest scope (AgentProvenance-style)", "agentnet")),
           cell = factor(cell, rev(c("E1 N3", "E5 sync", "E5 thread", "E5 subproc", "E5 async"))))
  g4 <- ggplot(bl, aes(I, cell, fill = mech)) +
    geom_col(position = position_dodge(width = 0.8), width = 0.75, colour = "white", linewidth = 0.3) +
    geom_text(aes(label = pct(I)), position = position_dodge(width = 0.8), hjust = -0.15, size = 2.3) +
    scale_x_continuous(labels = pct, limits = c(0, 1.12), breaks = c(0, 0.5, 1)) +
    scale_fill_manual(values = pal[c(2, 4, 1)]) +
    guides(fill = guide_legend(nrow = 2)) +
    labs(x = "connections credited to the wrong execution", y = NULL) + theme_paper()
  save_fig(g4, "fig_baselines", 2.05)
} else message("baselines.csv not found: run `snakemake baselines` first")

#+ session
sessionInfo()
