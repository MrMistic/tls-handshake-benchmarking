#!/usr/bin/env python3
"""
Stage 4: Read the JSON output from the handshake-timing tool and produce some charts.

Usage:
    python3 visualize.py results.json [--output-dir ./charts]
"""

import json
import os
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


def load_data(json_path: str) -> dict:
    """Load and validate the JSON results file."""
    if not os.path.exists(json_path):
        print(f"ERROR: File not found: {json_path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(json_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse {json_path}: {e}", file=sys.stderr)
        sys.exit(1)


def make_bar_chart(data: dict, output_dir: Path):
    """Grouped bar chart: mean duration per message, with error bars."""
    repro = data["reproducibility"]
    meta = data["metadata"]

    # Parse into lists
    messages = []
    roles = []
    means = []
    stddevs = []

    for key, stats in repro.items():
        # key format: MESSAGENAME_role
        parts = key.rsplit("_", 1)
        msg_name = parts[0]
        role = parts[1] if len(parts) > 1 else "unknown"
        messages.append(msg_name)
        roles.append(role)
        means.append(stats["mean_ns"] / 1000.0)  # convert to microseconds
        stddevs.append(stats["stddev_ns"] / 1000.0)

    df = pd.DataFrame({
        "Message": messages,
        "Role": roles,
        "Mean (µs)": means,
        "Stddev (µs)": stddevs,
    })

    # Sort by server first, then by mean descending
    df["sort_key"] = df["Role"].map({"server": 0, "client": 1})
    df = df.sort_values(["sort_key", "Mean (µs)"], ascending=[True, False])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

    # Server-side chart
    server_df = df[df["Role"] == "server"].copy()
    ax1.barh(
        server_df["Message"],
        server_df["Mean (µs)"],
        xerr=server_df["Stddev (µs)"],
        color=sns.color_palette("Blues_d", len(server_df)),
        edgecolor="black",
        linewidth=0.5,
    )
    ax1.set_xlabel("Duration (µs)")
    ax1.set_title(f"Server-side message timings\n{meta['cert_type']} / {meta['cpu_model']}")
    ax1.invert_yaxis()

    # Client-side chart
    client_df = df[df["Role"] == "client"].copy()
    ax2.barh(
        client_df["Message"],
        client_df["Mean (µs)"],
        xerr=client_df["Stddev (µs)"],
        color=sns.color_palette("Oranges_d", len(client_df)),
        edgecolor="black",
        linewidth=0.5,
    )
    ax2.set_xlabel("Duration (µs)")
    ax2.set_title(f"Client-side message timings\n{meta['cert_type']} / {meta['cpu_model']}")
    ax2.invert_yaxis()

    plt.tight_layout()
    out_path = output_dir / f"per_message_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def make_stacked_chart(data: dict, output_dir: Path):
    """Stacked bar chart: cumulative contribution of each message."""
    repro = data["reproducibility"]
    meta = data["metadata"]

    server_msgs = {}
    client_msgs = {}

    for key, stats in repro.items():
        parts = key.rsplit("_", 1)
        msg_name = parts[0]
        role = parts[1] if len(parts) > 1 else "unknown"
        mean_us = stats["mean_ns"] / 1000.0
        if role == "server":
            server_msgs[msg_name] = mean_us
        else:
            client_msgs[msg_name] = mean_us

    fig, ax = plt.subplots(figsize=(12, 6))

    # Sort messages by server cost descending
    all_msgs = sorted(
        set(list(server_msgs.keys()) + list(client_msgs.keys())),
        key=lambda m: server_msgs.get(m, 0),
        reverse=True,
    )

    colors = sns.color_palette("tab10", len(all_msgs))
    x = np.array([0, 1])
    width = 0.5

    bottom_server = 0.0
    bottom_client = 0.0

    for i, msg in enumerate(all_msgs):
        sv = server_msgs.get(msg, 0)
        cl = client_msgs.get(msg, 0)
        ax.bar(0, sv, width, bottom=bottom_server, label=msg, color=colors[i], edgecolor="white")
        ax.bar(1, cl, width, bottom=bottom_client, color=colors[i], edgecolor="white")
        bottom_server += sv
        bottom_client += cl

    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Server", "Client"])
    ax.set_ylabel("Duration (µs)")
    ax.set_title(
        f"Cumulative per-message handshake time\n"
        f"{meta['cert_type']} / {meta['measurement_iterations']} iterations"
    )
    ax.legend(loc="upper right", fontsize=8)

    plt.tight_layout()
    out_path = output_dir / f"stacked_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: visualize.py <results.json> [--output-dir <dir>]", file=sys.stderr)
        sys.exit(1)

    json_path = sys.argv[1]
    output_dir = Path("./charts")

    # Parse --output-dir
    for i, arg in enumerate(sys.argv):
        if arg == "--output-dir" and i + 1 < len(sys.argv):
            output_dir = Path(sys.argv[i + 1])

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Reading: {json_path}")
    print(f"Output:  {output_dir}/")

    data = load_data(json_path)

    make_bar_chart(data, output_dir)
    make_stacked_chart(data, output_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
