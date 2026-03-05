"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   PURDUE MODEL OT/IT NETWORK SIMULATION — MAIN RUNNER                       ║
║   Lean Automation · Industrial Cybersecurity Assessment                      ║
║                                                                              ║
║   USAGE:                                                                     ║
║     python run_simulation.py                    # run all 5 scenarios        ║
║     python run_simulation.py --scenario normal  # single scenario            ║
║     python run_simulation.py --list             # list available scenarios   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import argparse
import time

# Ensure local modules found
sys.path.insert(0, os.path.dirname(__file__))

from purdue_simulation import PurdueSimulator, SCENARIOS
from purdue_visualization import (
    plot_topology,
    plot_scenario_dashboard,
    plot_scenario_detail,
    plot_kill_chain,
)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def save(fig, name: str):
    path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"  → Saved: {path}")
    return path


def run_all(selected: list = None, quiet: bool = False):
    sim     = PurdueSimulator()
    results = {}

    keys = selected if selected else list(SCENARIOS.keys())

    print("\n" + "▓" * 72)
    print("  PURDUE MODEL SIMULATION ENGINE — Lean Automation")
    print("  OT/IT Cybersecurity Assessment Tool")
    print("▓" * 72)

    for key in keys:
        if key not in SCENARIOS:
            print(f"  [!] Unknown scenario: {key}")
            continue
        scenario = SCENARIOS[key]
        result   = sim.run(scenario, verbose=not quiet)
        results[key] = result

    if not results:
        print("No valid scenarios ran.")
        return

    print("\n" + "═" * 72)
    print("  GENERATING VISUALIZATIONS")
    print("═" * 72)

    # 1. Network topology
    print("\n  [1/4] Network topology diagram...")
    compromised = {
        name for name, node in sim.nodes.items() if node.compromised
    }
    breach_scenario = next(
        (k for k in ["attack_undefended", "hybrid", "attack_defended"]
         if k in results and results[k].breach_occurred), None
    )
    topo_title = (
        f"Purdue Model Network — Post-Attack Topology ({breach_scenario})"
        if breach_scenario
        else "Purdue Model Network Topology"
    )
    fig_topo = plot_topology(sim.nodes, compromised=compromised, title=topo_title)
    save(fig_topo, "01_network_topology.png")

    # 2. Multi-scenario dashboard
    print("  [2/4] Multi-scenario dashboard...")
    fig_dash = plot_scenario_dashboard(results)
    save(fig_dash, "02_scenario_dashboard.png")

    # 3. Per-scenario detail plots
    print("  [3/4] Per-scenario detail plots...")
    for key, result in results.items():
        fig_detail = plot_scenario_detail(result, key)
        save(fig_detail, f"03_detail_{key}.png")

    # 4. Kill chain diagram
    print("  [4/4] Kill chain diagrams...")
    if "attack_defended" in results:
        fig_kc = plot_kill_chain(results["attack_defended"], defended=True)
        save(fig_kc, "04_kill_chain_defended.png")
    if "attack_undefended" in results:
        fig_kc2 = plot_kill_chain(results["attack_undefended"], defended=False)
        save(fig_kc2, "04_kill_chain_undefended.png")
    elif results:
        # Use whatever attack scenario we have
        first_attack = next((k for k in results if "attack" in k or "hybrid" in k), None)
        if first_attack:
            fig_kc = plot_kill_chain(results[first_attack], defended="defended" in first_attack)
            save(fig_kc, "04_kill_chain.png")

    # Final text report
    _print_final_report(results)
    print(f"\n  All outputs saved to: {OUTPUT_DIR}/")
    print("═" * 72 + "\n")

    return results


def _print_final_report(results: dict):
    print("\n" + "═" * 72)
    print("  FINAL ASSESSMENT REPORT — PURDUE MODEL SIMULATION")
    print("═" * 72)

    header = f"  {'Scenario':<36} {'Breach':>8} {'CPU%':>6} {'Blk%':>6} {'Lat(ms)':>9} {'Pkts':>8}"
    print(header)
    print("  " + "─" * 70)

    for key, r in results.items():
        breach  = "YES ⚠" if r.breach_occurred else "No  ✓"
        cpu     = f"{r.avg_cpu_pct:.1f}"
        blk     = f"{r.dmz_block_rate*100:.0f}"
        lat     = f"{r.avg_latency_ms:.1f}"
        pkts    = f"{r.total_packets:,}"
        name    = r.scenario.name[:36]
        print(f"  {name:<36} {breach:>8} {cpu:>5}% {blk:>5}% {lat:>8} {pkts:>8}")

    print("  " + "─" * 70)

    # Key findings
    print("\n  KEY FINDINGS:")
    if "normal" in results and "high_load" in results:
        cpu_delta = results["high_load"].avg_cpu_pct - results["normal"].avg_cpu_pct
        lat_delta = results["high_load"].avg_latency_ms - results["normal"].avg_latency_ms
        print(f"  • High load increased avg CPU by +{cpu_delta:.1f}% and latency by +{lat_delta:.1f}ms")

    if "attack_defended" in results:
        r = results["attack_defended"]
        print(f"  • Defended posture: {r.dmz_block_rate:.1%} block rate — "
              f"{'Breach contained' if not r.breach_occurred else f'Breach at tick {r.breach_tick}'}")

    if "attack_undefended" in results:
        r = results["attack_undefended"]
        print(f"  • Undefended posture: {r.dmz_block_rate:.1%} block rate — "
              f"{'Breach occurred at tick ' + str(r.breach_tick) if r.breach_occurred else 'No breach (lucky)'}")

    if "attack_defended" in results and "attack_undefended" in results:
        def_r   = results["attack_defended"]
        undef_r = results["attack_undefended"]
        diff    = undef_r.total_blocked - def_r.total_blocked if undef_r.total_blocked > def_r.total_blocked else 0
        print(f"  • AI + Segmentation blocked {def_r.total_blocked - undef_r.total_blocked:+,} "
              f"additional packets vs undefended")

    if "hybrid" in results:
        r = results["hybrid"]
        print(f"  • Hybrid scenario (attack + high load): avg CPU {r.avg_cpu_pct:.1f}%, "
              f"{'breach occurred' if r.breach_occurred else 'no breach'}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Purdue Model OT/IT Network Simulation — Lean Automation"
    )
    parser.add_argument(
        "--scenario", "-s",
        nargs="+",
        help="Scenario key(s) to run (default: all)",
        choices=list(SCENARIOS.keys()),
        default=None,
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available scenarios and exit"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress per-tick output"
    )
    args = parser.parse_args()

    if args.list:
        print("\nAvailable Scenarios:")
        print("─" * 60)
        for key, s in SCENARIOS.items():
            print(f"  {key:<24} — {s.name}")
        print()
        return

    run_all(selected=args.scenario, quiet=args.quiet)


if __name__ == "__main__":
    main()
