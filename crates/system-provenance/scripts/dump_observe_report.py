#!/usr/bin/env python3
"""Dump a Flowguard JSON observe report into human log and graph files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


NODE_STYLE = {
    "file:": ("#ffe0d6", "SECRET file"),
    "proc:": ("#e8f2ff", "Process"),
    "pipe:": ("#fff1ba", "Pipe"),
    "endpoint:": ("#ffd6e7", "Network endpoint"),
}


def node_label(display: str) -> str:
    for prefix, (_, label) in NODE_STYLE.items():
        if display.startswith(prefix):
            return f"{label}\\n{display}"
    return display


def node_color(display: str) -> str:
    for prefix, (color, _) in NODE_STYLE.items():
        if display.startswith(prefix):
            return color
    return "#ffffff"


def mmd_label(display: str) -> str:
    return node_label(display).replace("\\n", "<br/>")


def load_first_violation(report: dict) -> tuple[dict, dict]:
    violations = report.get("violations") or []
    explanations = report.get("explanations") or []
    if not violations:
        raise SystemExit("report has no policy violations")
    if not explanations:
        raise SystemExit("report has no explanations")
    return violations[0], explanations[0]


def explanation_nodes(path: list[dict]) -> list[str]:
    nodes: list[str] = []
    for step in path:
        for key in ("from_display", "to_display"):
            display = step[key]
            if display not in nodes:
                nodes.append(display)
    return nodes


def write_log(path: Path, report: dict, violation: dict, explanation: dict) -> None:
    decision = report["decision"]["kind"].upper()
    lines = [
        "Flowguard Observe Violation Report",
        "",
        "Decision:",
        decision,
        "",
        "Violation:",
        f"policy: {violation['policy']}",
        f"sink_event_sequence: {violation['sink_event_sequence']}",
        f"sink_event: {violation['sink_event']['summary']}",
        f"sink_edge: {violation['sink_edge']}",
        "",
        "Sink:",
        explanation["sink_display"],
        "",
        "Reconstructed Explanation Path:",
    ]

    for step in explanation["path"]:
        lines.append(
            f"{step['from_display']} --{step['edge_kind'].upper()}--> {step['to_display']}"
        )

    lines.extend(
        [
            "",
            "Interpretation:",
            "SECRET propagated through observed provenance edges into a network SEND sink.",
            "The policy engine blocked the run because SecretToNetwork was violated.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_dot(path: Path, violation: dict, explanation: dict) -> None:
    nodes = explanation_nodes(explanation["path"])
    node_ids = {display: f"n{index}" for index, display in enumerate(nodes)}

    lines = [
        "digraph flowguard_violation {",
        '  graph [label="Flowguard SecretToNetwork Violation", labelloc=t, fontsize=20, rankdir=LR, bgcolor="#fffaf0"];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=12, color="#2f2a24", penwidth=1.5];',
        '  edge [fontname="Helvetica", fontsize=11, color="#6b4f2a", fontcolor="#4f3b1f", penwidth=2];',
        "",
    ]

    for display in nodes:
        lines.append(
            f'  {node_ids[display]} [label="{node_label(display)}", fillcolor="{node_color(display)}"];'
        )

    lines.append("")
    sink_edge = violation["sink_edge"]
    for step in explanation["path"]:
        color = '#b42318' if step["via_edge"] == sink_edge else '#6b4f2a'
        label = step["edge_kind"].upper()
        if step["via_edge"] == sink_edge:
            label = f"{label}\\nBLOCK SecretToNetwork"
        lines.append(
            f'  {node_ids[step["from_display"]]} -> {node_ids[step["to_display"]]} [label="{label}", color="{color}", fontcolor="{color}"];'
        )

    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_mermaid(path: Path, violation: dict, explanation: dict) -> None:
    nodes = explanation_nodes(explanation["path"])
    node_ids = {display: f"n{index}" for index, display in enumerate(nodes)}
    lines = ["flowchart LR"]

    for display in nodes:
        lines.append(f'  {node_ids[display]}["{mmd_label(display)}"]')

    sink_edge = violation["sink_edge"]
    for step in explanation["path"]:
        label = step["edge_kind"].upper()
        if step["via_edge"] == sink_edge:
            label = f"{label}<br/>BLOCK SecretToNetwork"
        lines.append(
            f'  {node_ids[step["from_display"]]} -- "{label}" --> {node_ids[step["to_display"]]}'
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path("logs"))
    parser.add_argument("--name", default="secret-to-network")
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    violation, explanation = load_first_violation(report)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    write_log(args.out_dir / f"{args.name}.violation.log", report, violation, explanation)
    write_dot(args.out_dir / f"{args.name}.graph.dot", violation, explanation)
    write_mermaid(args.out_dir / f"{args.name}.graph.mmd", violation, explanation)

    print(f"wrote {args.out_dir / f'{args.name}.violation.log'}")
    print(f"wrote {args.out_dir / f'{args.name}.graph.dot'}")
    print(f"wrote {args.out_dir / f'{args.name}.graph.mmd'}")


if __name__ == "__main__":
    main()
