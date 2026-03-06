"""
critical_path.py — Critical Path Method (CPM) analysis for CRYSTALS-KYBER DAG

Original contribution: computes the critical path through the Kyber
algorithm's task dependency graph using measured sub-task timings
from the task profiler.

Usage:
    python critical_path.py [--kyber-k 2|3|4] [--results-dir results/]

Requires: numpy (optional, for statistics)
"""

import json
import os
import sys
import argparse
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')

# ================================================================
#  DAG definitions (must match dag_tasks.h exactly)
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
    """Assign measured weights to DAG tasks. Returns list of (task, weight)."""
    weighted = []
    for task in dag:
        w = times.get(task["name"], 0.0)
        weighted.append({"id": task["id"], "name": task["name"],
                         "deps": task["deps"], "weight": w})
    return weighted


def compute_critical_path(dag):
    """
    Compute the critical path using forward-pass longest-path algorithm.

    Returns:
        - critical_path: list of task names on the critical path
        - est: earliest start times for each task
        - eft: earliest finish times for each task
        - makespan: total critical path length (infinite-core lower bound)
    """
    n = len(dag)
    est = [0.0] * n   # earliest start time
    eft = [0.0] * n   # earliest finish time

    # Forward pass: topological order (IDs are already topologically sorted)
    for task in dag:
        tid = task["id"]
        if task["deps"]:
            est[tid] = max(eft[dep] for dep in task["deps"])
        eft[tid] = est[tid] + task["weight"]

    makespan = max(eft)

    # Backward pass to find critical path
    lst = [0.0] * n   # latest start time
    lft = [0.0] * n   # latest finish time

    for i in range(n):
        lft[i] = makespan
        lst[i] = makespan

    # Find successors
    successors = defaultdict(list)
    for task in dag:
        for dep in task["deps"]:
            successors[dep].append(task["id"])

    # Backward pass
    for task in reversed(dag):
        tid = task["id"]
        if successors[tid]:
            lft[tid] = min(lst[s] for s in successors[tid])
        else:
            lft[tid] = makespan
        lst[tid] = lft[tid] - task["weight"]

    # Critical path: tasks where EST == LST (zero slack)
    critical = []
    for task in dag:
        tid = task["id"]
        slack = lst[tid] - est[tid]
        if abs(slack) < 1e-6:
            critical.append(task["name"])

    return critical, est, eft, makespan


def simulate_segatz_schedule(dag, assignment):
    """
    Simulate Segatz's empirical 2-core schedule.
    Tasks are assigned to cores per the assignment array.
    Each core processes its tasks in order, respecting dependencies.

    Returns makespan of the schedule.
    """
    n = len(dag)
    core_time = [0.0, 0.0]   # current time on each core
    finish_time = [0.0] * n   # when each task finishes

    # Process in topological order
    for task in dag:
        tid = task["id"]
        core = assignment[tid]

        # Earliest this task can start: max of core availability and all deps
        earliest = core_time[core]
        for dep in task["deps"]:
            earliest = max(earliest, finish_time[dep])

        finish_time[tid] = earliest + task["weight"]
        core_time[core] = finish_time[tid]

    return max(finish_time)


def compute_two_core_lower_bound(dag):
    """
    Lower bound for 2-core schedule:
    max(critical_path_length, total_work / 2)
    """
    _, _, _, cp_len = compute_critical_path(dag)
    total_work = sum(t["weight"] for t in dag)
    return max(cp_len, total_work / 2.0)


def analyze_operation(name, dag, times, segatz_assignment, report_lines):
    """Run full CPM analysis on one operation."""
    weighted = assign_weights(dag, times)
    critical, est, eft, makespan = compute_critical_path(weighted)
    total_work = sum(t["weight"] for t in weighted)
    lb2 = compute_two_core_lower_bound(weighted)
    segatz_time = simulate_segatz_schedule(weighted, segatz_assignment)

    report_lines.append(f"\n{'='*65}")
    report_lines.append(f"  {name}")
    report_lines.append(f"{'='*65}")
    report_lines.append("")

    # Task weights
    report_lines.append("  Task Weights (measured):")
    for t in weighted:
        marker = " <-- CRITICAL" if t["name"] in critical else ""
        report_lines.append(f"    {t['name']:<32s} {t['weight']:>10.2f} us{marker}")

    report_lines.append("")
    report_lines.append(f"  Total work:                    {total_work:>10.2f} us")
    report_lines.append(f"  Critical path length (1+ core):{makespan:>10.2f} us")
    report_lines.append(f"  2-core lower bound:            {lb2:>10.2f} us")
    report_lines.append(f"  Segatz schedule (2-core):       {segatz_time:>10.2f} us")
    report_lines.append(f"  Single-core (sequential):       {total_work:>10.2f} us")
    report_lines.append("")

    if segatz_time > 0:
        speedup_segatz = total_work / segatz_time
        speedup_optimal = total_work / lb2 if lb2 > 0 else 0
        gap = ((segatz_time - lb2) / lb2 * 100) if lb2 > 0 else 0

        report_lines.append(f"  Segatz speedup vs single-core: {speedup_segatz:>10.2f}x")
        report_lines.append(f"  Optimal speedup (theoretical): {speedup_optimal:>10.2f}x")
        report_lines.append(f"  Segatz gap from optimal:       {gap:>10.1f}%")
    else:
        report_lines.append("  (Cannot compute speedup — Segatz time is 0)")

    report_lines.append("")
    report_lines.append(f"  Critical path: {' → '.join(critical)}")

    return {
        "operation": name,
        "total_work": total_work,
        "critical_path_length": makespan,
        "two_core_lower_bound": lb2,
        "segatz_time": segatz_time,
        "critical_path": critical,
        "task_weights": {t["name"]: t["weight"] for t in weighted},
    }


def main():
    parser = argparse.ArgumentParser(description="Critical Path Method analysis for Kyber DAG")
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

    report = []
    report.append("=" * 65)
    report.append(f"  CRYSTALS-KYBER Critical Path Analysis — Kyber-{level}")
    report.append(f"  Data source: {json_path}")
    report.append("=" * 65)

    results = {}
    results["keypair"] = analyze_operation(
        f"Key Generation (Kyber-{level})",
        KEYPAIR_DAG, times, SEGATZ_KEYPAIR, report)
    results["encaps"] = analyze_operation(
        f"Encapsulation (Kyber-{level})",
        ENCAPS_DAG, times, SEGATZ_ENCAPS, report)
    results["decaps"] = analyze_operation(
        f"Decapsulation (Kyber-{level})",
        DECAPS_DAG, times, SEGATZ_DECAPS, report)

    # Summary
    report.append("")
    report.append("=" * 65)
    report.append("  SUMMARY")
    report.append("=" * 65)
    for op_name, r in results.items():
        gap = ((r["segatz_time"] - r["two_core_lower_bound"])
               / r["two_core_lower_bound"] * 100) if r["two_core_lower_bound"] > 0 else 0
        report.append(f"  {op_name:<12s}: Segatz {r['segatz_time']:.2f} us vs "
                      f"optimal {r['two_core_lower_bound']:.2f} us "
                      f"(gap: {gap:.1f}%)")
    report.append("")

    # Print and save
    report_text = "\n".join(report)
    print(report_text)

    out_path = os.path.join(args.results_dir, "critical_path_analysis.txt")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(report_text + "\n")
    print(f"\nReport saved to: {out_path}")

    # Also save JSON for list_scheduler.py
    json_out = os.path.join(args.results_dir, f"cpm_results_kyber{level}.json")
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"JSON saved to: {json_out}")


if __name__ == "__main__":
    main()
