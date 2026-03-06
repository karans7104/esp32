"""
list_scheduler.py — Optimal 2-core List Scheduling with Gantt chart

Original contribution: implements the standard List Scheduling heuristic
for 2 processors on the CRYSTALS-KYBER DAG, then compares the resulting
schedule against Segatz's empirical hand-partitioned schedule.

Generates:
  - results/optimal_schedule.png   (Gantt chart comparison)
  - results/schedule_comparison.txt (text report)

Usage:
    python list_scheduler.py [--kyber-k 2|3|4] [--results-dir results/]

Requires: matplotlib, numpy
"""

import json
import os
import sys
import argparse
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use('Agg')       # non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("WARNING: matplotlib not found — Gantt chart will be skipped.")
    print("         Install with: pip install matplotlib numpy")

# ================================================================
#  DAG definitions (must match dag_tasks.h and critical_path.py)
# ================================================================

KEYPAIR_DAG = [
    {"id": 0, "name": "KG.1_seed_expansion",  "deps": []},
    {"id": 1, "name": "KG.2_gen_matrix_A",    "deps": [0]},
    {"id": 2, "name": "KG.3_noise_s",         "deps": [0]},
    {"id": 3, "name": "KG.4_noise_e",         "deps": [0]},
    {"id": 4, "name": "KG.5_ntt_s",           "deps": [2]},
    {"id": 5, "name": "KG.6_ntt_e",           "deps": [3]},
    {"id": 6, "name": "KG.7_matmul_As",       "deps": [1, 4]},
    {"id": 7, "name": "KG.8_add_reduce",      "deps": [6, 5]},
    {"id": 8, "name": "KG.9_pack",            "deps": [7]},
]

ENCAPS_DAG = [
    {"id": 0, "name": "ENC.1_unpack_pk",       "deps": []},
    {"id": 1, "name": "ENC.2_gen_matrix_AT",   "deps": [0]},
    {"id": 2, "name": "ENC.3_noise_r",         "deps": [0]},
    {"id": 3, "name": "ENC.4_noise_e1",        "deps": [0]},
    {"id": 4, "name": "ENC.5_noise_e2",        "deps": [0]},
    {"id": 5, "name": "ENC.6_ntt_r",           "deps": [2]},
    {"id": 6, "name": "ENC.7_matmul_ATr",      "deps": [1, 5]},
    {"id": 7, "name": "ENC.8_inner_tTr",       "deps": [0, 5]},
    {"id": 8, "name": "ENC.9_invntt",          "deps": [6, 7]},
    {"id": 9, "name": "ENC.10_add_errors",     "deps": [8, 3, 4]},
    {"id": 10, "name": "ENC.11_compress_pack", "deps": [9]},
]

DECAPS_DAG = [
    {"id": 0, "name": "DEC.1_decompress_ct",   "deps": []},
    {"id": 1, "name": "DEC.2_unpack_sk",       "deps": []},
    {"id": 2, "name": "DEC.3_ntt_u",           "deps": [0]},
    {"id": 3, "name": "DEC.4_inner_sTu",       "deps": [1, 2]},
    {"id": 4, "name": "DEC.5_invntt",          "deps": [3]},
    {"id": 5, "name": "DEC.6_sub_reduce",      "deps": [4]},
    {"id": 6, "name": "DEC.7_decode_msg",      "deps": [5]},
]

SEGATZ_KEYPAIR = [0, 0, 1, 1, 1, 1, 0, 0, 0]
SEGATZ_ENCAPS  = [0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0]
SEGATZ_DECAPS  = [1, 0, 1, 0, 0, 0, 0]


def load_task_times(json_path):
    """Load measured task times from the profiler's JSON output."""
    with open(json_path, 'r') as f:
        data = json.load(f)
    times = {}
    for task in data["tasks"]:
        times[task["name"]] = task["avg_us"]
    return times


def assign_weights(dag, times):
    """Assign measured weights to DAG tasks."""
    weighted = []
    for task in dag:
        w = times.get(task["name"], 0.0)
        weighted.append({"id": task["id"], "name": task["name"],
                         "deps": list(task["deps"]), "weight": w})
    return weighted


def compute_bottom_level(dag):
    """
    Compute the bottom level (b-level) for each task.
    b-level(t) = weight(t) + max(b-level(s) for s in successors(t))

    This is used for priority in List Scheduling (HLFET heuristic).
    """
    n = len(dag)
    successors = defaultdict(list)
    for task in dag:
        for dep in task["deps"]:
            successors[dep].append(task["id"])

    blevel = [0.0] * n

    # Compute in reverse topological order
    for task in reversed(dag):
        tid = task["id"]
        if successors[tid]:
            blevel[tid] = task["weight"] + max(blevel[s] for s in successors[tid])
        else:
            blevel[tid] = task["weight"]

    return blevel


def list_schedule(dag, num_cores=2):
    """
    Standard List Scheduling with HLFET (Highest Level First with
    Estimated Times) priority.

    Returns:
        schedule: list of (task_id, core, start_time, end_time)
        makespan: total schedule length
    """
    n = len(dag)
    blevel = compute_bottom_level(dag)

    core_avail = [0.0] * num_cores
    finish_time = [0.0] * n
    scheduled = [False] * n

    schedule = []

    for _ in range(n):
        # Find ready tasks (all deps scheduled)
        ready = []
        for task in dag:
            tid = task["id"]
            if scheduled[tid]:
                continue
            if all(scheduled[dep] for dep in task["deps"]):
                ready.append(tid)

        if not ready:
            break

        # Sort by b-level (descending) — highest priority first
        ready.sort(key=lambda t: blevel[t], reverse=True)

        # Pick the highest priority ready task
        best_task = ready[0]
        task = dag[best_task]

        # Find earliest start: max of (core available, all deps finished)
        dep_finish = max((finish_time[d] for d in task["deps"]), default=0.0)

        # Find the core that gives earliest start
        best_core = -1
        best_start = float('inf')
        for c in range(num_cores):
            start = max(core_avail[c], dep_finish)
            if start < best_start:
                best_start = start
                best_core = c

        end = best_start + task["weight"]
        schedule.append((best_task, best_core, best_start, end))
        finish_time[best_task] = end
        core_avail[best_core] = end
        scheduled[best_task] = True

    makespan = max(e for _, _, _, e in schedule) if schedule else 0
    return schedule, makespan


def simulate_segatz(dag, assignment):
    """Simulate Segatz's fixed 2-core assignment."""
    n = len(dag)
    core_time = [0.0, 0.0]
    finish_time = [0.0] * n
    schedule = []

    for task in dag:
        tid = task["id"]
        core = assignment[tid]
        dep_finish = max((finish_time[d] for d in task["deps"]), default=0.0)
        start = max(core_time[core], dep_finish)
        end = start + task["weight"]

        schedule.append((tid, core, start, end))
        finish_time[tid] = end
        core_time[core] = end

    makespan = max(e for _, _, _, e in schedule) if schedule else 0
    return schedule, makespan


def draw_gantt(ax, schedule, dag, title, colors):
    """Draw a Gantt chart on the given axes."""
    for tid, core, start, end in schedule:
        task_name = dag[tid]["name"]
        short_name = task_name.split("_", 1)[0]  # e.g. "KG.1"
        duration = end - start

        bar = ax.barh(core, duration, left=start, height=0.6,
                      color=colors[tid % len(colors)], edgecolor='black',
                      linewidth=0.5, alpha=0.85)

        # Label inside bar if it's wide enough
        if duration > 0:
            ax.text(start + duration / 2, core, short_name,
                    ha='center', va='center', fontsize=6, fontweight='bold')

    ax.set_yticks([0, 1])
    ax.set_yticklabels(['Core 0', 'Core 1'])
    ax.set_xlabel('Time (μs)')
    ax.set_title(title, fontsize=10, fontweight='bold')
    ax.set_xlim(left=0)
    ax.invert_yaxis()


def generate_gantt_chart(results, output_path):
    """Generate a multi-panel Gantt chart comparing schedules."""
    if not HAS_MPL:
        return

    fig, axes = plt.subplots(3, 2, figsize=(16, 10))
    fig.suptitle('CRYSTALS-KYBER DAG Scheduling: Segatz vs Optimal',
                 fontsize=14, fontweight='bold')

    colors = plt.cm.Set3(np.linspace(0, 1, 12))

    ops = ["keypair", "encaps", "decaps"]
    op_labels = ["Key Generation", "Encapsulation", "Decapsulation"]

    for row, (op, label) in enumerate(zip(ops, op_labels)):
        r = results[op]
        dag = r["dag"]
        segatz_sched = r["segatz_schedule"]
        optimal_sched = r["optimal_schedule"]
        segatz_ms = r["segatz_makespan"]
        optimal_ms = r["optimal_makespan"]

        draw_gantt(axes[row][0], segatz_sched, dag,
                   f'{label} — Segatz ({segatz_ms:.1f} μs)', colors)
        draw_gantt(axes[row][1], optimal_sched, dag,
                   f'{label} — List Sched ({optimal_ms:.1f} μs)', colors)

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Gantt chart saved to: {output_path}")


def analyze_one(name, dag_template, times, segatz_assignment):
    """Run list scheduling and Segatz simulation for one operation."""
    dag = assign_weights(dag_template, times)
    total_work = sum(t["weight"] for t in dag)

    optimal_sched, optimal_ms = list_schedule(dag)
    segatz_sched, segatz_ms = simulate_segatz(dag, segatz_assignment)

    return {
        "dag": dag,
        "total_work": total_work,
        "optimal_schedule": optimal_sched,
        "optimal_makespan": optimal_ms,
        "segatz_schedule": segatz_sched,
        "segatz_makespan": segatz_ms,
    }


def main():
    parser = argparse.ArgumentParser(
        description="List Scheduling analysis for Kyber DAG")
    parser.add_argument("--kyber-k", type=int, choices=[2, 3, 4], default=2,
                        help="Security level (2=512, 3=768, 4=1024)")
    parser.add_argument("--results-dir", type=str, default="results",
                        help="Directory containing task_times JSON files")
    args = parser.parse_args()

    level = {2: 512, 3: 768, 4: 1024}[args.kyber_k]
    json_path = os.path.join(args.results_dir, f"task_times_kyber{level}.json")

    if not os.path.exists(json_path):
        print(f"ERROR: {json_path} not found. Run task_profiler first.")
        sys.exit(1)

    times = load_task_times(json_path)

    results = {}
    results["keypair"] = analyze_one("Key Generation", KEYPAIR_DAG, times,
                                      SEGATZ_KEYPAIR)
    results["encaps"] = analyze_one("Encapsulation", ENCAPS_DAG, times,
                                     SEGATZ_ENCAPS)
    results["decaps"] = analyze_one("Decapsulation", DECAPS_DAG, times,
                                     SEGATZ_DECAPS)

    # Print comparison report
    report = []
    report.append("=" * 70)
    report.append(f"  List Scheduling Analysis — Kyber-{level}")
    report.append("=" * 70)

    for op_name in ["keypair", "encaps", "decaps"]:
        r = results[op_name]
        report.append("")
        report.append(f"  {op_name.upper()}")
        report.append(f"  {'─' * 60}")
        report.append(f"    Total work:          {r['total_work']:>10.2f} μs")
        report.append(f"    Single-core time:    {r['total_work']:>10.2f} μs")
        report.append(f"    Segatz 2-core:       {r['segatz_makespan']:>10.2f} μs")
        report.append(f"    List Sched 2-core:   {r['optimal_makespan']:>10.2f} μs")

        if r['segatz_makespan'] > 0:
            seg_speedup = r['total_work'] / r['segatz_makespan']
            report.append(f"    Segatz speedup:      {seg_speedup:>10.2f}x")
        if r['optimal_makespan'] > 0:
            opt_speedup = r['total_work'] / r['optimal_makespan']
            report.append(f"    Optimal speedup:     {opt_speedup:>10.2f}x")
        if r['optimal_makespan'] > 0 and r['segatz_makespan'] > 0:
            gap_pct = ((r['segatz_makespan'] - r['optimal_makespan'])
                       / r['optimal_makespan'] * 100)
            report.append(f"    Gap (Segatz→Optimal):{gap_pct:>10.1f}%")

        # Show task assignments for both schedules
        report.append("")
        report.append("    Segatz assignment:")
        for tid, core, start, end in r["segatz_schedule"]:
            tname = r["dag"][tid]["name"]
            report.append(f"      Core {core}: {tname:<30s} "
                          f"[{start:.1f} → {end:.1f}] ({end-start:.1f} μs)")

        report.append("")
        report.append("    List Scheduling assignment:")
        for tid, core, start, end in r["optimal_schedule"]:
            tname = r["dag"][tid]["name"]
            report.append(f"      Core {core}: {tname:<30s} "
                          f"[{start:.1f} → {end:.1f}] ({end-start:.1f} μs)")

    report_text = "\n".join(report)
    print(report_text)

    # Save text report
    txt_path = os.path.join(args.results_dir, "schedule_comparison.txt")
    with open(txt_path, 'w') as f:
        f.write(report_text + "\n")
    print(f"\n  Report saved to: {txt_path}")

    # Generate Gantt chart
    if HAS_MPL:
        png_path = os.path.join(args.results_dir, "optimal_schedule.png")
        generate_gantt_chart(results, png_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
