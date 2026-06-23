#!/usr/bin/env python3
"""
Visualize handshake timing results.

IMPORTANT — methodology (see OPERATION_TIMING_METHODOLOGY.md and
comparison_methodology_decision.md):

  Per-message timings are NOT comparable across implementations. s2n-tls and
  rustls decompose the handshake state machine differently, so the same message
  name measures different work in each. Therefore:

  * Per-message charts (bar / stacked / timeline) are produced SEPARATELY per
    implementation — never overlaid — as WITHIN-implementation profiles only.
  * The cross-implementation comparison is OPERATION-LEVEL, derived from
    flamegraphs (see analyze_fg.py / OPERATION_LEVEL_RESULTS.md), not from
    per-message buckets.

Usage:
    python3 visualize.py results.json [--output-dir ./charts]

Output layout:
    charts/<cert_type>/<implementation>/per_message_*.png
                                        stacked_*.png
                                        timeline_*.png
                                        timeline_interactive_*.html
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


def implementations(data: dict) -> list:
    """Distinct implementations present in the measurements."""
    return sorted({m["implementation"] for m in data.get("measurements", [])})


def measurements_for(data: dict, impl: str) -> list:
    """All measurement records for one implementation."""
    return [m for m in data["measurements"] if m["implementation"] == impl]


def make_bar_chart(data: dict, impl: str, output_dir: Path):
    """Per-implementation grouped bar chart: mean duration per message."""
    meta = data["metadata"]
    rows = measurements_for(data, impl)

    dur_map = defaultdict(list)
    for m in rows:
        dur_map[(m["message_name"], m["role"])].append(m["duration_ns"] / 1000.0)

    messages, roles, means = [], [], []
    for (msg, role), vals in dur_map.items():
        messages.append(msg)
        roles.append(role)
        means.append(np.mean(vals))

    df = pd.DataFrame({"Message": messages, "Role": roles, "Mean (µs)": means})
    if df.empty:
        return
    df["sort_key"] = df["Role"].map({"server": 0, "client": 1})
    df = df.sort_values(["sort_key", "Mean (µs)"], ascending=[True, False])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

    server_df = df[df["Role"] == "server"]
    if not server_df.empty:
        ax1.barh(
            server_df["Message"], server_df["Mean (µs)"],
            color=sns.color_palette("Blues_d", len(server_df)),
            edgecolor="black", linewidth=0.5,
        )
    ax1.set_xlabel("Duration (µs)")
    ax1.set_title(f"{impl} — server-side message processing\n{meta['cert_type']} / {meta['cpu_model']}")
    ax1.invert_yaxis()

    client_df = df[df["Role"] == "client"]
    if not client_df.empty:
        ax2.barh(
            client_df["Message"], client_df["Mean (µs)"],
            color=sns.color_palette("Oranges_d", len(client_df)),
            edgecolor="black", linewidth=0.5,
        )
    ax2.set_xlabel("Duration (µs)")
    ax2.set_title(f"{impl} — client-side message processing\n{meta['cert_type']} / {meta['cpu_model']}")
    ax2.invert_yaxis()

    fig.suptitle(
        f"WITHIN-implementation profile ({impl}) — not a cross-impl comparison",
        fontsize=9, style="italic", color="#888", y=1.02,
    )
    plt.tight_layout()
    out_path = output_dir / f"per_message_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def make_stacked_chart(data: dict, impl: str, output_dir: Path):
    """Per-implementation stacked bar: cumulative contribution of each message."""
    meta = data["metadata"]
    rows = measurements_for(data, impl)

    dur_map = defaultdict(list)
    for m in rows:
        dur_map[(m["message_name"], m["role"])].append(m["duration_ns"] / 1000.0)
    means = {k: np.mean(v) for k, v in dur_map.items()}

    server_msgs, client_msgs = {}, {}
    for (msg, role), mean_us in means.items():
        (server_msgs if role == "server" else client_msgs)[msg] = mean_us

    if not server_msgs and not client_msgs:
        return

    fig, ax = plt.subplots(figsize=(12, 6))
    all_msgs = sorted(
        set(list(server_msgs) + list(client_msgs)),
        key=lambda m: server_msgs.get(m, 0), reverse=True,
    )
    colors = sns.color_palette("tab10", len(all_msgs))
    bottom_server = bottom_client = 0.0
    for i, msg in enumerate(all_msgs):
        sv = server_msgs.get(msg, 0)
        cl = client_msgs.get(msg, 0)
        ax.bar(0, sv, 0.5, bottom=bottom_server, label=msg, color=colors[i], edgecolor="white")
        ax.bar(1, cl, 0.5, bottom=bottom_client, color=colors[i], edgecolor="white")
        bottom_server += sv
        bottom_client += cl

    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Server", "Client"])
    ax.set_ylabel("Duration (µs)")
    ax.set_title(
        f"{impl} — cumulative per-message time (within-impl profile)\n"
        f"{meta['cert_type']} / {meta['measurement_iterations']} iterations"
    )
    ax.legend(loc="upper right", fontsize=8)

    plt.tight_layout()
    out_path = output_dir / f"stacked_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def _ordered_segments(rows):
    """Chronological (name, role) order from iteration 0 plus mean durations."""
    iter0 = [m for m in rows if m["iteration"] == 0]
    durations = defaultdict(list)
    for m in rows:
        durations[(m["message_name"], m["role"])].append(m["duration_ns"])
    means = {k: np.mean(v) for k, v in durations.items()}

    seen, ordered = set(), []
    for m in iter0:
        key = (m["message_name"], m["role"])
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered, means, durations


def make_timeline_chart(data: dict, impl: str, output_dir: Path):
    """Per-implementation single-row chronological timeline."""
    meta = data["metadata"]
    rows = measurements_for(data, impl)
    ordered, means, _ = _ordered_segments(rows)
    if not ordered:
        return

    total_ns = sum(means[k] for k in ordered)
    fig, ax = plt.subplots(figsize=(18, 3))
    server_color = sns.color_palette("Blues", 3)[1]
    client_color = sns.color_palette("Oranges", 3)[1]

    left = 0.0
    for name, role in ordered:
        us = means[(name, role)] / 1000.0
        pct = (means[(name, role)] / total_ns) * 100 if total_ns else 0
        color = server_color if role == "server" else client_color
        ax.barh(0, us, left=left, height=0.6, color=color, edgecolor="white", linewidth=0.5)
        if pct >= 2.0:
            short_role = "s" if role == "server" else "c"
            ax.text(left + us / 2, 0, f"{name}_{short_role}\n{pct:.1f}%",
                    ha="center", va="center", fontsize=7, fontweight="bold")
        left += us

    ax.set_xlim(0, left)
    ax.set_yticks([])
    ax.set_xlabel("Duration (µs)")
    ax.set_title(
        f"{impl} handshake timeline — {meta['cert_type']} / {meta['cpu_model']}\n"
        f"Blue = server, Orange = client (within-impl profile)",
        fontsize=11, fontweight="bold",
    )
    plt.tight_layout()
    out_path = output_dir / f"timeline_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def make_interactive_timeline(data: dict, impl: str, output_dir: Path):
    """Per-implementation interactive HTML timeline (click a segment -> histogram)."""
    meta = data["metadata"]
    rows = measurements_for(data, impl)
    ordered, means, durations = _ordered_segments(rows)
    if not ordered:
        return

    total_ns = sum(means[k] for k in ordered)
    segments = []
    for name, role in ordered:
        mean_us = means[(name, role)] / 1000.0
        pct = (means[(name, role)] / total_ns) * 100 if total_ns else 0
        short_role = "s" if role == "server" else "c"
        segments.append({
            "label": f"{name}_{short_role}",
            "name": name, "role": role,
            "mean_us": mean_us, "pct": pct,
            "values": [v / 1000.0 for v in durations[(name, role)]],
        })

    html = _build_interactive_html(segments, meta, impl)
    out_path = output_dir / f"timeline_interactive_{meta['cert_type']}.html"
    out_path.write_text(html)
    print(f"  ✓ {out_path}")


def _build_interactive_html(segments: list, meta: dict, impl: str) -> str:
    import json as _json
    segments_json = _json.dumps(segments)
    cert_type = meta["cert_type"]
    cpu_model = meta["cpu_model"]

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>{impl} Timeline — {cert_type}</title>
    <script src="https://cdn.plot.ly/plotly-2.35.0.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #fafafa; }}
        h2 {{ margin-bottom: 4px; }}
        .subtitle {{ color: #666; font-size: 14px; margin-bottom: 16px; }}
        #timeline {{ width: 100%; height: 180px; cursor: pointer; }}
        #histogram {{ width: 100%; height: 350px; }}
        .hint {{ color: #888; font-size: 12px; margin-top: 4px; }}
        .selector {{ margin: 10px 0; font-size: 14px; }}
        .selector select {{ padding: 4px 8px; font-size: 14px; border-radius: 4px; border: 1px solid #ccc; }}
    </style>
</head>
<body>
    <h2>{impl} Handshake Timeline — {cert_type}</h2>
    <div class="subtitle">{cpu_model} &nbsp;|&nbsp; Blue = server, Orange = client &nbsp;|&nbsp; within-implementation profile</div>
    <div id="timeline"></div>
    <div class="hint">Click a segment above, or pick a message below, to see its distribution.</div>
    <div class="selector">
        <label for="msgSelect">Message: </label>
        <select id="msgSelect"></select>
    </div>
    <div id="histogram"></div>

    <script>
    const segments = {segments_json};
    const serverColor = 'rgb(70, 130, 180)';
    const clientColor = 'rgb(230, 140, 60)';
    const serverColorLight = 'rgba(70, 130, 180, 0.3)';
    const clientColorLight = 'rgba(230, 140, 60, 0.3)';

    let left = 0;
    const timelineTraces = segments.map((seg, i) => {{
        const color = seg.role === 'server' ? serverColor : clientColor;
        const trace = {{
            x: [seg.mean_us], y: [''], type: 'bar', orientation: 'h', base: left,
            marker: {{ color: color, line: {{ color: 'white', width: 0.5 }} }},
            hovertemplate: '<b>' + seg.label + '</b><br>Mean: ' + seg.mean_us.toFixed(2) + ' µs<br>' + seg.pct.toFixed(1) + '% of handshake<extra></extra>',
            showlegend: false, name: seg.label,
        }};
        left += seg.mean_us;
        return trace;
    }});

    const annotations = [];
    let annotLeft = 0;
    segments.forEach(seg => {{
        if (seg.pct >= 2.0) {{
            annotations.push({{
                x: annotLeft + seg.mean_us / 2, y: '',
                text: seg.label + '<br>' + seg.pct.toFixed(1) + '%',
                showarrow: false, font: {{ size: 9, color: '#333' }},
                xanchor: 'center', yanchor: 'middle',
            }});
        }}
        annotLeft += seg.mean_us;
    }});

    const timelineLayout = {{
        barmode: 'stack',
        xaxis: {{ title: 'Duration (µs)' }},
        yaxis: {{ showticklabels: false }},
        margin: {{ t: 10, b: 40, l: 20, r: 20 }},
        annotations: annotations, height: 160,
    }};

    Plotly.newPlot('timeline', timelineTraces, timelineLayout, {{responsive: true}});

    const select = document.getElementById('msgSelect');
    segments.forEach((seg, i) => {{
        const opt = document.createElement('option');
        opt.value = i;
        opt.textContent = seg.label + ' (' + seg.mean_us.toFixed(2) + ' µs, ' + seg.pct.toFixed(1) + '%)';
        select.appendChild(opt);
    }});

    let largestIdx = 0, largestMean = 0;
    segments.forEach((seg, i) => {{ if (seg.mean_us > largestMean) {{ largestMean = seg.mean_us; largestIdx = i; }} }});
    select.value = largestIdx;
    showHistogram(largestIdx);
    highlightSegment(largestIdx);

    document.getElementById('timeline').on('plotly_click', function(eventData) {{
        const pointIdx = eventData.points[0].curveNumber;
        select.value = pointIdx;
        showHistogram(pointIdx);
        highlightSegment(pointIdx);
    }});

    select.addEventListener('change', function() {{
        const idx = parseInt(this.value, 10);
        showHistogram(idx);
        highlightSegment(idx);
    }});

    function showHistogram(idx) {{
        const seg = segments[idx];
        const color = seg.role === 'server' ? serverColor : clientColor;
        const trace = {{
            x: seg.values, type: 'histogram',
            marker: {{ color: color, opacity: 0.8 }},
            hovertemplate: 'Duration: %{{x:.2f}} µs<br>Count: %{{y}}<extra></extra>',
        }};
        const layout = {{
            title: {{ text: seg.label + ' — distribution (' + seg.values.length + ' samples, mean ' + seg.mean_us.toFixed(2) + ' µs)', font: {{ size: 14 }} }},
            xaxis: {{ title: 'Duration (µs)' }}, yaxis: {{ title: 'Count' }},
            margin: {{ t: 50, b: 50, l: 60, r: 20 }}, height: 340,
        }};
        Plotly.react('histogram', [trace], layout, {{responsive: true}});
    }}

    function highlightSegment(activeIdx) {{
        const colors = segments.map((seg, i) => {{
            if (i === activeIdx) return seg.role === 'server' ? serverColor : clientColor;
            return seg.role === 'server' ? serverColorLight : clientColorLight;
        }});
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
    for i, arg in enumerate(sys.argv):
        if arg == "--output-dir" and i + 1 < len(sys.argv):
            output_dir = Path(sys.argv[i + 1])

    print(f"Reading: {json_path}")
    data = load_data(json_path)

    cert_type = data.get("metadata", {}).get("cert_type", "unknown")
    impls = implementations(data)
    if not impls:
        print("ERROR: no measurements found in JSON", file=sys.stderr)
        sys.exit(1)

    print(f"Implementations: {', '.join(impls)}")
    print("NOTE: per-message charts are WITHIN-implementation profiles only.")
    print("      Cross-implementation comparison is operation-level (see analyze_fg.py).")

    # One subfolder per implementation: charts/<cert>/<impl>/
    for impl in impls:
        impl_dir = output_dir / cert_type / impl
        impl_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n[{impl}] -> {impl_dir}/")
        make_bar_chart(data, impl, impl_dir)
        make_stacked_chart(data, impl, impl_dir)
        make_timeline_chart(data, impl, impl_dir)
        make_interactive_timeline(data, impl, impl_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
