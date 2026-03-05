"""
Purdue Model Simulation — Visualization Engine
Generates all plots and the network topology diagram.
"""

from __future__ import annotations
import math
import statistics
from typing import Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
import matplotlib.gridspec as gridspec
from matplotlib.lines import Line2D
import networkx as nx

from purdue_simulation import (
    SimulationResult, Scenario, Level, LEVEL_NAMES, LEVEL_COLORS, SCENARIOS
)


# ─────────────────────────────────────────────────────────────────────────────
# STYLE
# ─────────────────────────────────────────────────────────────────────────────

BG       = "#0a0d12"
PANEL_BG = "#111620"
GRID_CLR = "#1e2535"
TEXT     = "#e2e8f0"
STEEL    = "#64748b"
GREEN    = "#10b981"
RED      = "#ef4444"
AMBER    = "#f59e0b"
BLUE     = "#3b82f6"
CYAN     = "#06b6d4"
PURPLE   = "#8b5cf6"

SCENARIO_COLORS = {
    "normal":            GREEN,
    "high_load":         AMBER,
    "attack_defended":   BLUE,
    "attack_undefended": RED,
    "hybrid":            PURPLE,
}

def _style():
    plt.rcParams.update({
        "figure.facecolor":  BG,
        "axes.facecolor":    PANEL_BG,
        "axes.edgecolor":    GRID_CLR,
        "axes.labelcolor":   TEXT,
        "axes.titlecolor":   TEXT,
        "axes.grid":         True,
        "grid.color":        GRID_CLR,
        "grid.linewidth":    0.6,
        "xtick.color":       STEEL,
        "ytick.color":       STEEL,
        "text.color":        TEXT,
        "legend.facecolor":  "#1a2035",
        "legend.edgecolor":  GRID_CLR,
        "legend.labelcolor": TEXT,
        "font.family":       "monospace",
    })


# ─────────────────────────────────────────────────────────────────────────────
# TOPOLOGY DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────

def plot_topology(nodes_dict: dict, compromised: Optional[set] = None,
                  title: str = "Purdue Model Network Topology") -> plt.Figure:
    _style()
    fig, ax = plt.subplots(figsize=(14, 10), facecolor=BG)
    ax.set_facecolor(BG)
    ax.set_title(title, color=TEXT, fontsize=14, fontweight="bold", pad=16)

    G = nx.DiGraph()

    level_order = [
        Level.ENTERPRISE, Level.DMZ, Level.INDUSTRIAL,
        Level.CONTROL, Level.FIELD_DEVICE, Level.PROCESS
    ]
    nodes_by_level: Dict[Level, List[str]] = {l: [] for l in level_order}
    for name, node in nodes_dict.items():
        nodes_by_level[node.level].append(name)
        G.add_node(name, level=node.level)

    # positions: levels on Y axis, spread on X
    pos = {}
    y_map = {Level.ENTERPRISE: 5, Level.DMZ: 4, Level.INDUSTRIAL: 3,
             Level.CONTROL: 2, Level.FIELD_DEVICE: 1, Level.PROCESS: 0}

    for lvl, names in nodes_by_level.items():
        y = y_map[lvl]
        n = len(names)
        for i, name in enumerate(names):
            x = (i - (n - 1) / 2) * 2.0
            pos[name] = (x, y)

    # Edges: connect adjacent levels
    edge_pairs = [
        (Level.ENTERPRISE, Level.DMZ),
        (Level.DMZ, Level.INDUSTRIAL),
        (Level.INDUSTRIAL, Level.CONTROL),
        (Level.CONTROL, Level.FIELD_DEVICE),
        (Level.FIELD_DEVICE, Level.PROCESS),
    ]
    for upper, lower in edge_pairs:
        upper_nodes = nodes_by_level[upper]
        lower_nodes = nodes_by_level[lower]
        for un in upper_nodes[:2]:
            for ln in lower_nodes[:2]:
                G.add_edge(un, ln)

    # Draw level bands
    band_colors = {
        Level.ENTERPRISE:   (0.23, 0.50, 0.96, 0.08),
        Level.DMZ:          (0.94, 0.27, 0.27, 0.12),
        Level.INDUSTRIAL:   (0.96, 0.62, 0.07, 0.08),
        Level.CONTROL:      (0.96, 0.62, 0.07, 0.06),
        Level.FIELD_DEVICE: (0.06, 0.73, 0.51, 0.08),
        Level.PROCESS:      (0.06, 0.73, 0.51, 0.10),
    }
    for lvl, y in y_map.items():
        rect = mpatches.FancyBboxPatch(
            (-6, y - 0.42), 12, 0.84,
            boxstyle="round,pad=0.05",
            linewidth=1,
            edgecolor=LEVEL_COLORS[lvl] + "60",
            facecolor=band_colors[lvl],
            zorder=0,
        )
        ax.add_patch(rect)
        ax.text(-5.8, y, LEVEL_NAMES[lvl], color=LEVEL_COLORS[lvl],
                fontsize=8, va="center", fontweight="bold", zorder=2)

    # Draw edges
    nx.draw_networkx_edges(
        G, pos, ax=ax,
        edge_color=GRID_CLR, arrows=True,
        arrowsize=12, width=0.8,
        connectionstyle="arc3,rad=0.05",
        min_source_margin=18, min_target_margin=18
    )

    # Node colors
    node_colors  = []
    node_sizes   = []
    node_borders = []
    compromised  = compromised or set()

    for name in G.nodes():
        node = nodes_dict[name]
        base_color = LEVEL_COLORS[node.level]
        if name in compromised:
            node_colors.append(RED)
            node_borders.append(RED)
            node_sizes.append(600)
        else:
            node_colors.append(base_color)
            node_borders.append(base_color)
            node_sizes.append(450)

    nx.draw_networkx_nodes(
        G, pos, ax=ax,
        node_color=node_colors,
        node_size=node_sizes,
        edgecolors=node_borders,
        linewidths=2,
        alpha=0.85,
    )
    nx.draw_networkx_labels(
        G, pos, ax=ax,
        font_size=6.5, font_color="#ffffff",
        font_weight="bold",
    )

    # DMZ line
    ax.axhline(y=3.5, color=RED, linewidth=1.5, linestyle="--", alpha=0.7, zorder=1)
    ax.text(4.8, 3.55, "── DMZ BOUNDARY ──", color=RED, fontsize=8, va="bottom")

    # Legend
    legend_patches = [
        mpatches.Patch(color=BLUE,   label="Enterprise (L4-5)"),
        mpatches.Patch(color=RED,    label="DMZ (L3.5)"),
        mpatches.Patch(color=AMBER,  label="Industrial (L3) / Control (L2)"),
        mpatches.Patch(color=GREEN,  label="Field (L1) / Process (L0)"),
        mpatches.Patch(color=RED,    label="⚠ Compromised Node", linestyle="--"),
    ]
    ax.legend(handles=legend_patches, loc="upper right", fontsize=8)

    ax.set_xlim(-7, 7)
    ax.set_ylim(-0.6, 5.6)
    ax.axis("off")
    fig.tight_layout()
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def plot_scenario_dashboard(results: Dict[str, SimulationResult]) -> plt.Figure:
    _style()
    fig = plt.figure(figsize=(18, 14), facecolor=BG)
    fig.suptitle(
        "PURDUE MODEL — SCENARIO ASSESSMENT DASHBOARD",
        color=TEXT, fontsize=15, fontweight="bold", y=0.98
    )

    gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.45, wspace=0.35,
                           left=0.07, right=0.97, top=0.94, bottom=0.06)

    # ── Panel 1: Throughput over time ──
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.set_title("Network Throughput (packets/tick)", fontsize=10, pad=6)
    for key, r in results.items():
        color = SCENARIO_COLORS.get(key, STEEL)
        ticks = list(range(len(r.throughput_ts)))
        ax1.plot(ticks, _smooth(r.throughput_ts, 5),
                 color=color, linewidth=1.6, label=r.scenario.name, alpha=0.9)
    ax1.set_xlabel("Simulation Tick"); ax1.set_ylabel("Packets / Tick")
    ax1.legend(fontsize=7, loc="upper left")

    # ── Panel 2: Summary bar chart ──
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.set_title("Avg CPU Load by Scenario", fontsize=10, pad=6)
    keys   = list(results.keys())
    cpus   = [results[k].avg_cpu_pct for k in keys]
    colors = [SCENARIO_COLORS.get(k, STEEL) for k in keys]
    bars   = ax2.bar(range(len(keys)), cpus, color=colors, width=0.6, alpha=0.85)
    ax2.set_xticks(range(len(keys)))
    ax2.set_xticklabels([results[k].scenario.name.split("—")[0].strip()[:18]
                         for k in keys], rotation=25, ha="right", fontsize=7)
    ax2.set_ylabel("CPU %")
    ax2.axhline(80, color=RED, linewidth=1, linestyle="--", alpha=0.5)
    ax2.text(len(keys) - 0.5, 81, "danger", color=RED, fontsize=7)
    for bar, v in zip(bars, cpus):
        ax2.text(bar.get_x() + bar.get_width() / 2, v + 1, f"{v:.0f}%",
                 ha="center", fontsize=7, color=TEXT)

    # ── Panel 3: Latency over time ──
    ax3 = fig.add_subplot(gs[1, :2])
    ax3.set_title("Network Latency (ticks × 10 ms)", fontsize=10, pad=6)
    for key, r in results.items():
        color = SCENARIO_COLORS.get(key, STEEL)
        ticks = list(range(len(r.latency_ts)))
        ax3.plot(ticks, _smooth(r.latency_ts, 5),
                 color=color, linewidth=1.4, label=r.scenario.name, alpha=0.85)
    ax3.set_xlabel("Simulation Tick"); ax3.set_ylabel("Latency")
    ax3.legend(fontsize=7, loc="upper left")

    # ── Panel 4: DMZ block effectiveness ──
    ax4 = fig.add_subplot(gs[1, 2])
    ax4.set_title("DMZ Block Rate", fontsize=10, pad=6)
    block_rates = [results[k].dmz_block_rate * 100 for k in keys]
    bars2 = ax4.bar(range(len(keys)), block_rates, color=colors, width=0.6, alpha=0.85)
    ax4.set_xticks(range(len(keys)))
    ax4.set_xticklabels([results[k].scenario.name.split("—")[0].strip()[:18]
                         for k in keys], rotation=25, ha="right", fontsize=7)
    ax4.set_ylabel("% Packets Blocked at DMZ")
    ax4.set_ylim(0, 105)
    for bar, v in zip(bars2, block_rates):
        ax4.text(bar.get_x() + bar.get_width() / 2, v + 1, f"{v:.0f}%",
                 ha="center", fontsize=7, color=TEXT)

    # ── Panel 5: Attack vs blocked time series (attack scenarios only) ──
    ax5 = fig.add_subplot(gs[2, :2])
    ax5.set_title("Attack Packets vs Blocked — Attack Scenarios", fontsize=10, pad=6)
    for key in ["attack_defended", "attack_undefended", "hybrid"]:
        if key not in results:
            continue
        r     = results[key]
        color = SCENARIO_COLORS.get(key, STEEL)
        ticks = list(range(len(r.attack_ts)))
        ax5.plot(ticks, _smooth(r.attack_ts, 4),
                 color=color, linewidth=1.4, linestyle="-",
                 label=f"{r.scenario.name.split('—')[0].strip()} — attack", alpha=0.8)
        ax5.plot(ticks, _smooth(r.blocked_ts, 4),
                 color=color, linewidth=1.0, linestyle="--",
                 label=f"{r.scenario.name.split('—')[0].strip()} — blocked", alpha=0.6)
        # Breach marker
        if r.breach_occurred and r.breach_tick:
            ax5.axvline(r.breach_tick, color=color, linewidth=1.5,
                        linestyle=":", alpha=0.9)
            ax5.text(r.breach_tick + 1, ax5.get_ylim()[1] * 0.8,
                     "BREACH", color=color, fontsize=7, rotation=90)
    ax5.set_xlabel("Simulation Tick"); ax5.set_ylabel("Packets / Tick")
    ax5.legend(fontsize=6.5, loc="upper left", ncol=2)

    # ── Panel 6: Summary scorecard ──
    ax6 = fig.add_subplot(gs[2, 2])
    ax6.set_facecolor(PANEL_BG)
    ax6.axis("off")
    ax6.set_title("Security Scorecard", fontsize=10, pad=6)

    rows = [["Scenario", "Breach?", "Blk%", "CPU%", "Drop"]]
    for key, r in results.items():
        breach  = "⚠ YES" if r.breach_occurred else "✓ No"
        blk_pct = f"{r.dmz_block_rate*100:.0f}%"
        cpu_pct = f"{r.avg_cpu_pct:.0f}%"
        drop    = str(r.total_dropped)
        short   = r.scenario.name.split("—")[0].strip()[:16]
        rows.append([short, breach, blk_pct, cpu_pct, drop])

    col_widths = [0.38, 0.18, 0.14, 0.14, 0.12]
    row_h = 0.13
    for i, row in enumerate(rows):
        y = 0.92 - i * row_h
        bg = "#1e2535" if i % 2 == 0 else PANEL_BG
        ax6.add_patch(mpatches.FancyBboxPatch(
            (0, y - 0.01), 1, row_h - 0.01,
            boxstyle="square,pad=0", facecolor=bg, edgecolor="none"))
        x = 0.01
        for j, (cell, cw) in enumerate(zip(row, col_widths)):
            c = TEXT if i == 0 else (RED if "YES" in str(cell) else (GREEN if "✓" in str(cell) else STEEL))
            ax6.text(x, y + 0.03, cell, fontsize=7, color=c, va="center",
                     fontweight="bold" if i == 0 else "normal")
            x += cw

    # watermark
    fig.text(0.5, 0.01, "LEAN AUTOMATION — Purdue Model OT Simulation Engine",
             ha="center", fontsize=8, color=STEEL, style="italic")
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# PER-SCENARIO DETAIL PLOT
# ─────────────────────────────────────────────────────────────────────────────

def plot_scenario_detail(r: SimulationResult, key: str) -> plt.Figure:
    _style()
    fig = plt.figure(figsize=(16, 10), facecolor=BG)
    color = SCENARIO_COLORS.get(key, BLUE)

    fig.suptitle(
        f"SCENARIO DETAIL: {r.scenario.name.upper()}",
        color=TEXT, fontsize=13, fontweight="bold", y=0.98
    )

    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.42, wspace=0.35,
                           left=0.07, right=0.97, top=0.93, bottom=0.08)

    ticks = list(range(r.ticks))

    # ── CPU heatmap (top-3 nodes) ──
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.set_title("CPU Load — Key Nodes over Time", fontsize=10, pad=6)
    key_nodes = ["SCADA_SERVER", "ENG_WS", "CORP_EMAIL", "PLC_WELD", "SAFETY_SIS"]
    node_colors_map = [BLUE, AMBER, GREEN, CYAN, PURPLE]
    for node_name, nc in zip(key_nodes, node_colors_map):
        if node_name in r.cpu_ts and r.cpu_ts[node_name]:
            ts = r.cpu_ts[node_name]
            ax1.plot(ticks[:len(ts)], _smooth(ts, 5),
                     color=nc, linewidth=1.4, label=node_name, alpha=0.85)
    if r.breach_occurred and r.breach_tick:
        ax1.axvline(r.breach_tick, color=RED, linewidth=2, linestyle="--")
        ax1.text(r.breach_tick + 1, 85, "⚠ BREACH", color=RED, fontsize=8)
    ax1.set_xlabel("Tick"); ax1.set_ylabel("CPU %")
    ax1.set_ylim(0, 105)
    ax1.axhline(80, color=RED, alpha=0.3, linewidth=0.8, linestyle=":")
    ax1.legend(fontsize=8, loc="upper left")

    # ── Queue depth ──
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.set_title("Queue Depth", fontsize=10, pad=6)
    for node_name, nc in zip(key_nodes[:3], node_colors_map[:3]):
        if node_name in r.queue_ts and r.queue_ts[node_name]:
            ts = r.queue_ts[node_name]
            ax2.plot(ticks[:len(ts)], ts, color=nc, linewidth=1.2,
                     label=node_name, alpha=0.8)
    ax2.set_xlabel("Tick"); ax2.set_ylabel("Queue Depth (packets)")
    ax2.legend(fontsize=8)

    # ── Throughput ──
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.set_title("Throughput", fontsize=10, pad=6)
    ax3.fill_between(ticks, _smooth(r.throughput_ts, 5),
                     color=color, alpha=0.3)
    ax3.plot(ticks, _smooth(r.throughput_ts, 5), color=color, linewidth=1.5)
    ax3.set_xlabel("Tick"); ax3.set_ylabel("Pkts/Tick")

    # ── Attack / Blocked ──
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.set_title("Attack Traffic vs Blocked", fontsize=10, pad=6)
    ax4.fill_between(ticks, _smooth(r.attack_ts, 4),
                     color=RED, alpha=0.25, label="Attack pkts")
    ax4.plot(ticks, _smooth(r.attack_ts, 4), color=RED, linewidth=1.2)
    ax4.fill_between(ticks, _smooth(r.blocked_ts, 4),
                     color=GREEN, alpha=0.2, label="Blocked")
    ax4.plot(ticks, _smooth(r.blocked_ts, 4), color=GREEN, linewidth=1.2)
    if r.breach_occurred and r.breach_tick:
        ax4.axvline(r.breach_tick, color=RED, linewidth=1.5, linestyle="--")
    ax4.legend(fontsize=8)
    ax4.set_xlabel("Tick"); ax4.set_ylabel("Pkts/Tick")

    # ── Stats panel ──
    ax5 = fig.add_subplot(gs[1, 2])
    ax5.axis("off")
    ax5.set_title("Metrics Summary", fontsize=10, pad=6)

    stats = [
        ("Total Packets",    f"{r.total_packets:,}",            TEXT),
        ("Attack Packets",   f"{r.total_attack_pkts:,}",        RED if r.total_attack_pkts else TEXT),
        ("Total Blocked",    f"{r.total_blocked:,}",            GREEN),
        ("Total Dropped",    f"{r.total_dropped:,}",            AMBER),
        ("Avg Latency",      f"{r.avg_latency_ms:.2f} ms",      TEXT),
        ("Avg CPU",          f"{r.avg_cpu_pct:.1f}%",           AMBER if r.avg_cpu_pct > 70 else TEXT),
        ("DMZ Block Rate",   f"{r.dmz_block_rate:.1%}",         GREEN),
        ("Breach",           "YES ⚠" if r.breach_occurred else "No ✓",
                             RED if r.breach_occurred else GREEN),
        ("Kill Chain Stage", f"{r.kill_chain_stages_reached}/7" if r.kill_chain_stages_reached else "N/A", TEXT),
    ]

    for i, (label, value, c) in enumerate(stats):
        y = 0.92 - i * 0.105
        ax5.text(0.02, y, label + ":", fontsize=9, color=STEEL, va="center")
        ax5.text(0.98, y, value,       fontsize=9, color=c,     va="center", ha="right", fontweight="bold")
        ax5.axhline(y - 0.04, color=GRID_CLR, linewidth=0.5, alpha=0.5)

    fig.text(0.5, 0.01, f"Lean Automation · Scenario: {r.scenario.name}",
             ha="center", fontsize=8, color=STEEL, style="italic")
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# KILL CHAIN DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────

def plot_kill_chain(result: SimulationResult, defended: bool = True) -> plt.Figure:
    _style()
    fig, ax = plt.subplots(figsize=(14, 5), facecolor=BG)
    ax.set_facecolor(BG)
    ax.axis("off")
    ax.set_title(
        f"SloppyLemming Kill Chain — {'DEFENDED' if defended else 'UNDEFENDED'}",
        color=TEXT, fontsize=12, fontweight="bold", pad=10
    )

    stages = [
        ("Spear\nPhish",      "L4-5\nEnterprise"),
        ("PDF Lure\nClickOnce","L4-5\nEnterprise"),
        ("DLL\nSideload",     "L4-5\nEnterprise"),
        ("BurrowShell\nC2",   "L4-5\nEnterprise"),
        ("Keylogger\nExfil",  "L4-5\nEnterprise"),
        ("Lateral\nMove",     "L3.5\nDMZ"),
        ("OT\nBreach",        "L3\nIndustrial"),
    ]

    reached = result.kill_chain_stages_reached
    n       = len(stages)
    xs      = [i / (n - 1) for i in range(n)]
    y       = 0.5

    for i, (label, zone) in enumerate(stages):
        x = xs[i]
        active   = i <= reached
        blocked  = defended and i >= 5 and active
        color    = (RED if blocked else (AMBER if active else STEEL))

        # Arrow
        if i < n - 1:
            arrow_color = RED if (defended and i >= 5) else (color if active else GRID_CLR)
            ax.annotate(
                "", xy=(xs[i + 1], y), xytext=(x, y),
                arrowprops=dict(
                    arrowstyle="->",
                    color=arrow_color,
                    lw=2.0,
                    connectionstyle="arc3,rad=0"
                ),
                xycoords="axes fraction", textcoords="axes fraction"
            )

        # Node circle
        circle = plt.Circle((x, y), 0.045, color=color,
                             transform=ax.transAxes, zorder=3, alpha=0.85)
        ax.add_patch(circle)

        # Stage number
        ax.text(x, y, str(i + 1), ha="center", va="center",
                fontsize=9, fontweight="bold", color=BG,
                transform=ax.transAxes, zorder=4)

        # Label below
        ax.text(x, y - 0.22, label, ha="center", va="top",
                fontsize=8, color=color, transform=ax.transAxes,
                fontweight="bold" if active else "normal")

        # Zone above
        ax.text(x, y + 0.18, zone, ha="center", va="bottom",
                fontsize=7, color=STEEL, transform=ax.transAxes)

        # Block indicator
        if defended and i == 5:
            ax.text(x, y + 0.32, "🛡 BLOCKED\nby DMZ + AI",
                    ha="center", va="bottom", fontsize=8,
                    color=GREEN, transform=ax.transAxes, fontweight="bold")

    legend = [
        Line2D([0], [0], color=AMBER, linewidth=2, label="Kill chain progressed"),
        Line2D([0], [0], color=RED,   linewidth=2, label="Blocked / Denied"),
        Line2D([0], [0], color=STEEL, linewidth=2, label="Not reached"),
    ]
    ax.legend(handles=legend, loc="lower right", fontsize=8,
              bbox_to_anchor=(0.99, 0.02), framealpha=0.5)

    fig.tight_layout()
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _smooth(data: list, window: int = 5) -> list:
    if not data or window < 2:
        return data
    result = []
    for i in range(len(data)):
        lo = max(0, i - window // 2)
        hi = min(len(data), i + window // 2 + 1)
        result.append(statistics.mean(data[lo:hi]))
    return result
