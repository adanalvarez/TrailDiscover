#!/usr/bin/env python3
"""
TrailDiscover Build Pipeline
=============================
Single tool that runs the full build pipeline for TrailDiscover:

  1. format     – Normalize JSON formatting of all event files
  2. redact     – Redact sensitive data from .json.cloudtrail files
  3. copy-logs  – Copy .json.cloudtrail files to docs/logExamples
  4. generate   – Generate events.json, events.csv, and datadog_dashboard.json

Usage:
    python build.py                  # Run all steps
    python build.py --steps format redact copy-logs generate
    python build.py --steps format   # Run only formatting
    python build.py --on-the-wild-only  # Dashboard only with wild events
    python build.py --tactics "TA0003 - Persistence" "TA0040 - Impact"
"""

import argparse
import csv
import json
import os
import re
import shutil
import sys
from typing import Any, List, Optional

# ---------------------------------------------------------------------------
# Paths (relative to this script, which lives in tools/)
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
EVENTS_DIR = os.path.join(ROOT_DIR, "events")
DOCS_DIR = os.path.join(ROOT_DIR, "docs")
LOG_EXAMPLES_DIR = os.path.join(DOCS_DIR, "logExamples")
EVENTS_JSON = os.path.join(DOCS_DIR, "events.json")
EVENTS_CSV = os.path.join(DOCS_DIR, "events.csv")
DASHBOARD_JSON = os.path.join(DOCS_DIR, "datadog_dashboard.json")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def iter_event_files(extension: str = ".json"):
    """Yield (full_path, filename) for every file matching *extension* under EVENTS_DIR."""
    for root, _dirs, files in os.walk(EVENTS_DIR):
        for fname in sorted(files):
            if fname.endswith(extension) and not fname.endswith(".json.cloudtrail"):
                if extension == ".json":
                    yield os.path.join(root, fname), fname
            elif extension == ".json.cloudtrail" and fname.endswith(".json.cloudtrail"):
                yield os.path.join(root, fname), fname


# =====================================================================
# STEP 1 – Format
# =====================================================================

def step_format():
    """Re-write every .json event file with consistent 4-space indentation."""
    print("\n[ Step 1/4 ] Formatting event JSON files …")
    count = 0
    for fpath, _ in iter_event_files(".json"):
        with open(fpath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        with open(fpath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4)
            fh.write("\n")
        count += 1
    print(f"  ✓ Formatted {count} event files.")


# =====================================================================
# STEP 2 – Redact CloudTrail logs
# =====================================================================

PLACEHOLDERS = {
    "accountId": "111111111111",
    "recipientAccountId": "111111111111",
    "accessKeyId": "AKIA****************",
    "principalId": "AROA****************:User",
    "sourceIPAddress": "0.0.0.0",
    "ip": "0.0.0.0",
}
IP_REGEX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
ACCOUNT_REGEX = re.compile(r"arn:aws:[a-z0-9-]+::(\d{12}):")
SENSITIVE_KEYS = set(PLACEHOLDERS.keys())


def _redact_value(key: str, value: Any) -> Any:
    if value is None:
        return value
    if key in PLACEHOLDERS:
        return PLACEHOLDERS[key]
    if isinstance(value, str):
        value = IP_REGEX.sub(PLACEHOLDERS["sourceIPAddress"], value)
        def _acct_sub(m):
            return m.group(0).replace(m.group(1), PLACEHOLDERS["accountId"])
        value = ACCOUNT_REGEX.sub(_acct_sub, value)
    return value


def _walk_redact(obj: Any):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            v = obj[k]
            if isinstance(v, (dict, list)):
                _walk_redact(v)
            else:
                obj[k] = _redact_value(k, v)
    elif isinstance(obj, list):
        for i in range(len(obj)):
            v = obj[i]
            if isinstance(v, (dict, list)):
                _walk_redact(v)
            else:
                obj[i] = _redact_value("value", v)


def step_redact():
    """Redact sensitive information from all .json.cloudtrail files."""
    print("\n[ Step 2/4 ] Redacting CloudTrail log files …")
    modified = []
    for fpath, _ in iter_event_files(".json.cloudtrail"):
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.loads(fh.read().strip())
        except Exception:
            continue
        original = json.dumps(data, sort_keys=True)
        _walk_redact(data)
        redacted = json.dumps(data, sort_keys=True)
        if redacted != original:
            with open(fpath, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=4)
                fh.write("\n")
            modified.append(fpath)
    print(f"  ✓ Redacted {len(modified)} CloudTrail files.")
    for m in modified:
        print(f"    - {os.path.relpath(m, ROOT_DIR)}")


# =====================================================================
# STEP 3 – Copy CloudTrail logs to docs/logExamples
# =====================================================================

def step_copy_logs():
    """Copy all .json.cloudtrail files into docs/logExamples/."""
    print("\n[ Step 3/4 ] Copying CloudTrail logs to docs/logExamples …")
    os.makedirs(LOG_EXAMPLES_DIR, exist_ok=True)
    count = 0
    for fpath, fname in iter_event_files(".json.cloudtrail"):
        dest = os.path.join(LOG_EXAMPLES_DIR, fname)
        shutil.copy2(fpath, dest)
        count += 1
    print(f"  ✓ Copied {count} CloudTrail log files.")


# =====================================================================
# STEP 4 – Generate events.json, events.csv and datadog_dashboard.json
# =====================================================================

def _load_all_events() -> List[dict]:
    """Load every .json event file into a list."""
    events = []
    for fpath, _ in iter_event_files(".json"):
        with open(fpath, "r", encoding="utf-8") as fh:
            events.append(json.load(fh))
    return events


# --- events.json (for the web) -----------------------------------------

def _generate_events_json(events: List[dict]):
    with open(EVENTS_JSON, "w", encoding="utf-8") as fh:
        json.dump(events, fh, indent=4)
        fh.write("\n")
    print(f"  ✓ Generated {os.path.relpath(EVENTS_JSON, ROOT_DIR)} ({len(events)} events)")


# --- events.csv --------------------------------------------------------

CSV_HEADERS = [
    "eventName", "eventSource", "awsService", "description",
    "mitreAttackTactics", "mitreAttackTechniques", "mitreAttackSubTechniques",
    "usedInWild", "incidents", "researchLinks", "securityImplications",
    "alerting", "simulation", "permissions", "unverifiedMitreAttackTechniques",
]


def _generate_events_csv(events: List[dict]):
    with open(EVENTS_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for event in events:
            row = dict(event)
            row["mitreAttackTactics"] = ", ".join(row.get("mitreAttackTactics", []))
            row["mitreAttackTechniques"] = ", ".join(row.get("mitreAttackTechniques", []))
            row["mitreAttackSubTechniques"] = ", ".join(row.get("mitreAttackSubTechniques", []))
            row["incidents"] = json.dumps(row.get("incidents", []))
            row["researchLinks"] = json.dumps(row.get("researchLinks", []))
            row["alerting"] = json.dumps(row.get("alerting", []))
            row["simulation"] = json.dumps(row.get("simulation", []))
            row["unverifiedMitreAttackTechniques"] = json.dumps(row.get("unverifiedMitreAttackTechniques", []))
            writer.writerow(row)
    print(f"  ✓ Generated {os.path.relpath(EVENTS_CSV, ROOT_DIR)}")


# --- Datadog dashboard -------------------------------------------------

TACTIC_ORDER = {
    "TA0001 - Initial Access": 1,
    "TA0002 - Execution": 2,
    "TA0003 - Persistence": 3,
    "TA0004 - Privilege Escalation": 4,
    "TA0005 - Defense Evasion": 5,
    "TA0006 - Credential Access": 6,
    "TA0007 - Discovery": 7,
    "TA0008 - Lateral Movement": 8,
    "TA0009 - Collection": 9,
    "TA0011 - Command and Control": 10,
    "TA0010 - Exfiltration": 11,
    "TA0040 - Impact": 12,
}


def _group_events_by_tactics(events, filter_tactics=None):
    tactics = {}
    for event in events:
        for tactic in event.get("mitreAttackTactics", []):
            if filter_tactics and tactic not in filter_tactics:
                continue
            tactics.setdefault(tactic, []).append(event)
    return tactics


def _exploited_event_names(events):
    return [e["eventName"] for e in events if e.get("usedInWild", False)]


def _dd_base():
    return {
        "title": "TrailDiscover AWS Events Insights",
        "description": "",
        "widgets": [],
        "layout_type": "ordered",
        "template_variables": [
            {"name": "userIdentity.arn", "prefix": "@userIdentity.arn", "available_values": [], "default": "*"},
            {"name": "network.client.ip", "prefix": "@network.client.ip", "available_values": [], "default": "*"},
            {"name": "account", "prefix": "account", "available_values": [], "default": "*"},
        ],
        "notify_list": [],
        "reflow_type": "fixed",
    }


def _dd_logo():
    return {
        "id": 2066777487,
        "definition": {
            "type": "image", "url": "https://traildiscover.cloud/logo.png",
            "sizing": "contain", "margin": "md", "has_background": False,
            "has_border": False, "vertical_align": "center", "horizontal_align": "center",
        },
        "layout": {"x": 0, "y": 0, "width": 6, "height": 2},
    }


def _dd_description():
    return {
        "id": 2066777488,
        "definition": {
            "type": "note",
            "content": (
                " # [TrailDiscover](https://traildiscover.cloud/)\n\n"
                "This dashboard, built using data from traildiscover.cloud, offers a detailed "
                "visualization of AWS CloudTrail events that have been utilized or are potentially "
                "used by attackers. Events are organized according to MITRE ATT&CK tactics. Each "
                "event is presented with two widgets: one provides a description, a direct link to "
                "traildiscover.cloud, and references to related incidents and research; the other "
                "features a counter displaying the frequency of these events in your AWS environment."
            ),
            "background_color": "white", "font_size": "14", "text_align": "left",
            "vertical_align": "top", "show_tick": False, "tick_pos": "50%",
            "tick_edge": "left", "has_padding": True,
        },
        "layout": {"x": 0, "y": 2, "width": 6, "height": 3},
    }


def _dd_top_ten(names):
    return {
        "id": 2985843941260464,
        "definition": {
            "title": "Top 10 CloudTrail Events exploited in the wild",
            "title_size": "16", "title_align": "left", "type": "toplist",
            "requests": [{
                "queries": [{
                    "data_source": "logs", "name": "query1", "indexes": ["*"],
                    "compute": {"aggregation": "count"},
                    "group_by": [{"facet": "@evt.name", "limit": 10, "sort": {"order": "desc", "aggregation": "count"}}],
                    "search": {"query": f"source:cloudtrail @evt.name:({' OR '.join(names)}) $userIdentity.arn $network.client.ip $account"},
                }],
                "response_format": "scalar",
            }],
            "style": {"display": {"type": "stacked", "legend": "automatic"}},
        },
        "layout": {"x": 0, "y": 0, "width": 6, "height": 2},
    }


def _dd_timeline(tactics):
    formulas, queries = [], []
    for idx, (tactic, events) in enumerate(tactics.items(), start=1):
        names = [e["eventName"] for e in events]
        formulas.append({"alias": tactic, "formula": f"query{idx}"})
        queries.append({
            "data_source": "logs", "name": f"query{idx}", "indexes": ["*"],
            "compute": {"aggregation": "count"},
            "search": {"query": f"source:cloudtrail @evt.name:({' OR '.join(names)}) $userIdentity.arn $network.client.ip $account"},
            "group_by": [], "storage": "hot",
        })
    return {
        "id": 8265946211738036,
        "definition": {
            "title": "MITRE ATT&CK Tactics Events Timeline",
            "title_size": "16", "title_align": "left",
            "show_legend": True, "legend_layout": "auto",
            "legend_columns": ["avg", "min", "max", "value", "sum"],
            "time": {}, "type": "timeseries",
            "requests": [{
                "formulas": formulas, "queries": queries,
                "response_format": "timeseries",
                "style": {"palette": "dog_classic", "line_type": "solid", "line_width": "normal"},
                "display_type": "bars",
            }],
        },
        "layout": {"x": 0, "y": 2, "width": 6, "height": 2},
    }


def _dd_tactic_widgets(event, tactic, x, y):
    note_content = (
        f"### [{event['eventName']}](https://traildiscover.cloud/#{event['awsService']}-{event['eventName']})\n\n"
        f"**Description:** {event['description']}\n\n"
    )
    if event.get("incidents"):
        note_content += "**Related Incidents:**\n" + "".join(
            f"- [{i['description']}]({i['link']})\n" for i in event["incidents"]
        )
    if event.get("researchLinks"):
        note_content += "**Related Research:**\n" + "".join(
            f"- [{r['description']}]({r['link']})\n" for r in event["researchLinks"]
        )
    note = {
        "id": hash((tactic, event["eventName"], "note")) & 0xFFFFFFFF,
        "definition": {
            "type": "note", "content": note_content,
            "background_color": "white", "font_size": "14",
            "text_align": "left", "vertical_align": "top",
            "show_tick": False, "has_padding": True,
        },
        "layout": {"x": x, "y": y, "width": 2, "height": 2},
    }
    query = {
        "id": hash((tactic, event["eventName"], "query")) & 0xFFFFFFFF,
        "definition": {
            "title": event["eventName"], "title_size": "16", "title_align": "left",
            "type": "query_value",
            "requests": [{
                "response_format": "scalar",
                "queries": [{
                    "data_source": "logs", "name": "query1", "indexes": ["*"],
                    "compute": {"aggregation": "count"},
                    "search": {"query": f"source:cloudtrail @evt.name:{event['eventName']} $userIdentity.arn $network.client.ip $account"},
                }],
                "formulas": [{"formula": "query1"}],
            }],
            "autoscale": True, "precision": 2,
        },
        "layout": {"x": x + 2, "y": y, "width": 2, "height": 2},
    }
    return [note, query]


def _dd_create_tactic_group_widgets(tactic, events):
    widgets = []
    x, y = 0, 0
    for event in events:
        if x + 4 > 12:
            x, y = 0, y + 2
        widgets.extend(_dd_tactic_widgets(event, tactic, x, y))
        x += 4
    return widgets, y + 2


def _generate_datadog_dashboard(events, filter_tactics=None, wild_only=False):
    if wild_only:
        events = [e for e in events if e.get("usedInWild", False)]

    tactics = _group_events_by_tactics(events, filter_tactics)
    exploited = _exploited_event_names(events)

    dashboard = _dd_base()
    dashboard["widgets"].append(_dd_logo())

    overview = [_dd_timeline(tactics), _dd_top_ten(exploited)]
    dashboard["widgets"].append({
        "id": 8265946211738038,
        "definition": {
            "type": "group", "layout_type": "ordered",
            "background_color": "blue", "title": "Overview", "show_title": True,
            "widgets": overview,
        },
        "layout": {"x": 6, "y": 0, "width": 6, "height": 5},
    })

    dashboard["widgets"].append(_dd_description())

    y_pos = 5
    for tactic, tevents in sorted(tactics.items(), key=lambda x: TACTIC_ORDER.get(x[0], 999)):
        group_widgets, row_h = _dd_create_tactic_group_widgets(tactic, tevents)
        dashboard["widgets"].append({
            "id": hash(tactic) & 0xFFFFFFFF,
            "definition": {
                "type": "group", "layout_type": "ordered",
                "background_color": "blue", "title": tactic, "show_title": True,
                "widgets": group_widgets,
            },
            "layout": {"x": 0, "y": y_pos, "width": 12, "height": row_h + 2},
        })
        y_pos += row_h + 2

    with open(DASHBOARD_JSON, "w", encoding="utf-8") as fh:
        json.dump(dashboard, fh, indent=4)
        fh.write("\n")
    print(f"  ✓ Generated {os.path.relpath(DASHBOARD_JSON, ROOT_DIR)}")


def step_generate(filter_tactics=None, wild_only=False):
    """Generate events.json, events.csv, and datadog_dashboard.json."""
    print("\n[ Step 4/4 ] Generating output files …")
    events = _load_all_events()
    _generate_events_json(events)
    _generate_events_csv(events)
    _generate_datadog_dashboard(events, filter_tactics=filter_tactics, wild_only=wild_only)


# =====================================================================
# CLI
# =====================================================================

ALL_STEPS = ["format", "redact", "copy-logs", "generate"]


def main():
    parser = argparse.ArgumentParser(
        description="TrailDiscover build pipeline – format, redact, copy, and generate all outputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--steps", nargs="+", choices=ALL_STEPS, default=ALL_STEPS,
        help="Steps to run (default: all). Choices: format, redact, copy-logs, generate",
    )
    parser.add_argument(
        "--on-the-wild-only", action="store_true",
        help="Dashboard: include only events seen in the wild.",
    )
    parser.add_argument(
        "--tactics", nargs="+",
        help="Dashboard: filter to specific MITRE ATT&CK tactics.",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  TrailDiscover Build Pipeline")
    print("=" * 60)
    print(f"  Events dir : {EVENTS_DIR}")
    print(f"  Docs dir   : {DOCS_DIR}")
    print(f"  Steps      : {', '.join(args.steps)}")

    if "format" in args.steps:
        step_format()
    if "redact" in args.steps:
        step_redact()
    if "copy-logs" in args.steps:
        step_copy_logs()
    if "generate" in args.steps:
        step_generate(filter_tactics=args.tactics, wild_only=args.on_the_wild_only)

    print("\n" + "=" * 60)
    print("  ✅ Build complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
