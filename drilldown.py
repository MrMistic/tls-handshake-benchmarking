#!/usr/bin/env python3
"""Drill into a subtree: for stacks passing through <anchor>, attribute samples
to the deepest frame (leaf) and report where the subtree's time goes."""
import sys
from collections import defaultdict

folded_path = sys.argv[1]
anchor = sys.argv[2]  # substring identifying the subtree root, e.g. validate_cert_chain

total_all = 0
subtree_total = 0
leaf_counts = defaultdict(int)
# Also: for stacks under the anchor, what is the frame immediately below it?
child_counts = defaultdict(int)

with open(folded_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        stack, _, cnt = line.rpartition(" ")
        try:
            cnt = int(cnt)
        except ValueError:
            continue
        total_all += cnt
        frames = stack.split(";")
        # find anchor frame index
        idx = next((i for i, fr in enumerate(frames) if anchor in fr), None)
        if idx is None:
            continue
        subtree_total += cnt
        leaf_counts[frames[-1]] += cnt
        if idx + 1 < len(frames):
            child_counts[frames[idx + 1]] += cnt

print(f"anchor: '{anchor}'")
print(f"total samples:    {total_all}")
print(f"subtree samples:  {subtree_total}  ({100*subtree_total/total_all:.2f}% of all)")
print(f"\n-- immediate children of anchor (where it dispatches) --")
for fn, c in sorted(child_counts.items(), key=lambda x: -x[1])[:15]:
    print(f"  {100*c/subtree_total:5.1f}%  {c:>10}  {fn[:72]}")
print(f"\n-- leaf functions within the subtree (where cycles burn) --")
for fn, c in sorted(leaf_counts.items(), key=lambda x: -x[1])[:20]:
    print(f"  {100*c/subtree_total:5.1f}%  {c:>10}  {fn[:72]}")
