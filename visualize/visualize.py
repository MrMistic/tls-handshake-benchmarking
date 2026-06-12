#!/usr/bin/env python3
"""
Stage 4: Read the JSON output from the handshake-timing tool and produce some charts.

Usage:
    python3 visualize.py results.json [--output-dir ./charts]
"""

import json
import os
import sys
from collections import defaultdict
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
    """Grouped bar chart: mean duration per message, with min/max error bars."""
    meta = data["metadata"]
    measurements = data["measurements"]

    # Compute mean, p5, p95 per (message_name, role).
    dur_map = defaultdict(list)
    for m in measurements:
        key = (m["message_name"], m["role"])
        dur_map[key].append(m["duration_ns"] / 1000.0)  # microseconds

    messages = []
    roles = []
    means = []
    p5s = []
    p95s = []

    for (msg, role), vals in dur_map.items():
        messages.append(msg)
        roles.append(role)
        means.append(np.mean(vals))
        p5s.append(np.percentile(vals, 5))
        p95s.append(np.percentile(vals, 95))

    df = pd.DataFrame({
        "Message": messages,
        "Role": roles,
        "Mean (µs)": means,
        "P5 (µs)": p5s,
        "P95 (µs)": p95s,
    })

    # Sort by server first, then by mean descending
    df["sort_key"] = df["Role"].map({"server": 0, "client": 1})
    df = df.sort_values(["sort_key", "Mean (µs)"], ascending=[True, False])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

    # Server-side chart
    server_df = df[df["Role"] == "server"].copy()
    # server_xerr_low = (server_df["Mean (µs)"] - server_df["P5 (µs)"]).values
    # server_xerr_high = (server_df["P95 (µs)"] - server_df["Mean (µs)"]).values
    ax1.barh(
        server_df["Message"],
        server_df["Mean (µs)"],
        # xerr=[server_xerr_low, server_xerr_high],
        color=sns.color_palette("Blues_d", len(server_df)),
        edgecolor="black",
        linewidth=0.5,
    )
    ax1.set_xlabel("Duration (µs)")
    ax1.set_title(f"Server-side message timings\n{meta['cert_type']} / {meta['cpu_model']}")
    ax1.invert_yaxis()

    # Client-side chart
    client_df = df[df["Role"] == "client"].copy()
    # client_xerr_low = (client_df["Mean (µs)"] - client_df["P5 (µs)"]).values
    # client_xerr_high = (client_df["P95 (µs)"] - client_df["Mean (µs)"]).values
    ax2.barh(
        client_df["Message"],
        client_df["Mean (µs)"],
        # xerr=[client_xerr_low, client_xerr_high],
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


def make_timeline_chart(data: dict, output_dir: Path):
    """Timeline chart: single horizontal segmented bar showing all checkpoints in chronological order."""
    meta = data["metadata"]
    measurements = data["measurements"]

    # Use iteration 0 to determine the canonical chronological ordering.
    iter0 = [m for m in measurements if m["iteration"] == 0]
    order = [(m["message_name"], m["role"]) for m in iter0]

    # Compute mean duration for each (name, role) pair across all iterations.
    durations = defaultdict(list)
    for m in measurements:
        key = (m["message_name"], m["role"])
        durations[key].append(m["duration_ns"])

    means = {}
    for key, vals in durations.items():
        means[key] = np.mean(vals)

    # Deduplicate preserving first occurrence.
    seen = set()
    ordered_keys = []
    for key in order:
        if key not in seen:
            seen.add(key)
            ordered_keys.append(key)

    # Compute total and build segments.
    total_ns = sum(means[k] for k in ordered_keys)
    segments = []
    for key in ordered_keys:
        mean_ns = means[key]
        pct = (mean_ns / total_ns) * 100 if total_ns > 0 else 0
        name, role = key
        segments.append((name, role, mean_ns / 1000.0, pct))

    # Single-row timeline, color-coded by role.
    fig, ax = plt.subplots(figsize=(18, 3))

    server_color = sns.color_palette("Blues", 3)[1]
    client_color = sns.color_palette("Oranges", 3)[1]

    left = 0.0
    for name, role, us, pct in segments:
        color = server_color if role == "server" else client_color
        ax.barh(
            0, us, left=left, height=0.6,
            color=color, edgecolor="white", linewidth=0.5,
        )
        # Label segments wide enough to read.
        if pct >= 2.0:
            short_role = "s" if role == "server" else "c"
            ax.text(
                left + us / 2, 0,
                f"{name}_{short_role}\n{pct:.1f}%",
                ha="center", va="center", fontsize=7, fontweight="bold",
            )
        left += us

    ax.set_xlim(0, left)
    ax.set_yticks([])
    ax.set_xlabel("Duration (µs)")
    ax.set_title(
        f"Handshake timeline — {meta['cert_type']} / {meta['cpu_model']}\n"
        f"Blue = server, Orange = client",
        fontsize=11, fontweight="bold",
    )

    plt.tight_layout()
    out_path = output_dir / f"timeline_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def make_interactive_timeline(data: dict, output_dir: Path):
    """Interactive HTML timeline. Click a segment in the timeline to show its distribution below."""
    meta = data["metadata"]
    measurements = data["measurements"]

    # Determine chronological order from iteration 0.
    iter0 = [m for m in measurements if m["iteration"] == 0]
    seen = set()
    ordered_keys = []
    for m in iter0:
        key = (m["message_name"], m["role"])
        if key not in seen:
            seen.add(key)
            ordered_keys.append(key)

    # Compute per-(name, role) durations.
    dur_map = defaultdict(list)
    for m in measurements:
        key = (m["message_name"], m["role"])
        dur_map[key].append(m["duration_ns"])

    means = {k: np.mean(v) for k, v in dur_map.items()}
    total_ns = sum(means[k] for k in ordered_keys)

    # Build segment data for the JS.
    segments = []
    for name, role in ordered_keys:
        mean_us = means[(name, role)] / 1000.0
        pct = (means[(name, role)] / total_ns) * 100
        short_role = "s" if role == "server" else "c"
        label = f"{name}_{short_role}"
        vals_us = [v / 1000.0 for v in dur_map[(name, role)]]
        segments.append({
            "label": label,
            "name": name,
            "role": role,
            "mean_us": mean_us,
            "pct": pct,
            "values": vals_us,
        })

    # Generate self-contained HTML with Plotly + click handler.
    html = _build_interactive_html(segments, meta)
    out_path = output_dir / f"timeline_interactive_{meta['cert_type']}.html"
    out_path.write_text(html)
    print(f"  ✓ {out_path}")


def _build_interactive_html(segments: list, meta: dict) -> str:
    """Build a self-contained HTML page with clickable timeline and histogram."""
    import json as _json

    segments_json = _json.dumps(segments)
    cert_type = meta["cert_type"]
    cpu_model = meta["cpu_model"]

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Handshake Timeline — {cert_type}</title>
    <script src="https://cdn.plot.ly/plotly-2.35.0.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #fafafa; }}
        h2 {{ margin-bottom: 4px; }}
        .subtitle {{ color: #666; font-size: 14px; margin-bottom: 16px; }}
        #timeline {{ width: 100%; height: 180px; cursor: pointer; }}
        #histogram {{ width: 100%; height: 350px; }}
        .hint {{ color: #888; font-size: 12px; margin-top: 4px; }}
    </style>
</head>
<body>
    <h2>Handshake Timeline — {cert_type}</h2>
    <div class="subtitle">{cpu_model} &nbsp;|&nbsp; Blue = server, Orange = client</div>
    <div id="timeline"></div>
    <div class="hint">Click a segment above to see its distribution below.</div>
    <div id="histogram"></div>

    <script>
    const segments = {segments_json};
    const serverColor = 'rgb(70, 130, 180)';
    const clientColor = 'rgb(230, 140, 60)';
    const serverColorLight = 'rgba(70, 130, 180, 0.3)';
    const clientColorLight = 'rgba(230, 140, 60, 0.3)';

    // Build timeline traces (one bar per segment, stacked).
    let left = 0;
    const timelineTraces = segments.map((seg, i) => {{
        const color = seg.role === 'server' ? serverColor : clientColor;
        const trace = {{
            x: [seg.mean_us],
            y: [''],
            type: 'bar',
            orientation: 'h',
            base: left,
            marker: {{ color: color, line: {{ color: 'white', width: 0.5 }} }},
            hovertemplate: '<b>' + seg.label + '</b><br>Mean: ' + seg.mean_us.toFixed(2) + ' µs<br>' + seg.pct.toFixed(1) + '% of handshake<extra></extra>',
            showlegend: false,
            name: seg.label,
        }};
        left += seg.mean_us;
        return trace;
    }});

    // Add text annotations for segments >= 2%.
    const annotations = [];
    let annotLeft = 0;
    segments.forEach(seg => {{
        if (seg.pct >= 2.0) {{
            annotations.push({{
                x: annotLeft + seg.mean_us / 2,
                y: '',
                text: seg.label + '<br>' + seg.pct.toFixed(1) + '%',
                showarrow: false,
                font: {{ size: 9, color: '#333' }},
                xanchor: 'center',
                yanchor: 'middle',
            }});
        }}
        annotLeft += seg.mean_us;
    }});

    const timelineLayout = {{
        barmode: 'stack',
        xaxis: {{ title: 'Duration (µs)' }},
        yaxis: {{ showticklabels: false }},
        margin: {{ t: 10, b: 40, l: 20, r: 20 }},
        annotations: annotations,
        height: 160,
    }};

    Plotly.newPlot('timeline', timelineTraces, timelineLayout, {{responsive: true}});

    // Initial histogram: show the largest segment.
    let largestIdx = 0;
    let largestMean = 0;
    segments.forEach((seg, i) => {{
        if (seg.mean_us > largestMean) {{
            largestMean = seg.mean_us;
            largestIdx = i;
        }}
    }});
    showHistogram(largestIdx);

    // Click handler on timeline.
    document.getElementById('timeline').on('plotly_click', function(eventData) {{
        const pointIdx = eventData.points[0].curveNumber;
        showHistogram(pointIdx);
        highlightSegment(pointIdx);
    }});

    function showHistogram(idx) {{
        const seg = segments[idx];
        const color = seg.role === 'server' ? serverColor : clientColor;
        const trace = {{
            x: seg.values,
            type: 'histogram',
            marker: {{ color: color, opacity: 0.8 }},
            hovertemplate: 'Duration: %{{x:.2f}} µs<br>Count: %{{y}}<extra></extra>',
        }};
        const layout = {{
            title: {{ text: seg.label + ' — distribution (' + seg.values.length + ' samples, mean ' + seg.mean_us.toFixed(2) + ' µs)', font: {{ size: 14 }} }},
            xaxis: {{ title: 'Duration (µs)' }},
            yaxis: {{ title: 'Count' }},
            margin: {{ t: 50, b: 50, l: 60, r: 20 }},
            height: 340,
        }};
        Plotly.react('histogram', [trace], layout, {{responsive: true}});
    }}

    function highlightSegment(activeIdx) {{
        const colors = segments.map((seg, i) => {{
            if (i === activeIdx) {{
                return seg.role === 'server' ? serverColor : clientColor;
            }} else {{
                return seg.role === 'server' ? serverColorLight : clientColorLight;
            }}
        }});
        const update = {{ 'marker.color': colors.map(c => [c]) }};
        // Update each trace individually.
        for (let i = 0; i < segments.length; i++) {{
            Plotly.restyle('timeline', {{ 'marker.color': [colors[i]] }}, [i]);
        }}
    }}
    </script>
</body>
</html>"""


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

    print(f"Reading: {json_path}")

    data = load_data(json_path)

    # Create a subfolder based on cert_type from the results metadata.
    cert_type = data.get("metadata", {}).get("cert_type", "unknown")
    output_dir = output_dir / cert_type
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output:  {output_dir}/")

    make_bar_chart(data, output_dir)
    make_stacked_chart(data, output_dir)
    make_timeline_chart(data, output_dir)
    make_interactive_timeline(data, output_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
