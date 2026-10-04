#!/usr/bin/env python3
"""
Download a pinned MITRE ATT&CK Enterprise release and write the small lookup that
build.py uses: tactic names and short names, technique names, and the tactics each
technique belongs to. Revoked and deprecated techniques are left out.

The lookup is committed (tools/attack/), so build.py never needs network access.
Run this only when moving TrailDiscover to a new ATT&CK version.

Usage:
    python3 updateAttackLookup.py                 # default version (see ATTACK_VERSION)
    python3 updateAttackLookup.py --version 18.1
"""

import argparse
import json
import os
import urllib.request

ATTACK_VERSION = "18.1"
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{version}.json"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(SCRIPT_DIR, "attack")


def _attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_lookup(bundle, version):
    objects = bundle["objects"]
    tactics = {}
    shortname_to_id = {}
    for obj in objects:
        if obj["type"] == "x-mitre-tactic" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            tid = _attack_id(obj)
            tactics[tid] = {"name": obj["name"], "shortname": obj["x_mitre_shortname"]}
            shortname_to_id[obj["x_mitre_shortname"]] = tid

    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _attack_id(obj)
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        techniques[tid] = {
            "name": obj["name"],
            "tactics": sorted(shortname_to_id[p] for p in phases if p in shortname_to_id),
        }

    return {
        "attackVersion": version,
        "source": STIX_URL.format(version=version),
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default=ATTACK_VERSION, help="ATT&CK Enterprise version, e.g. 18.1")
    args = parser.parse_args()

    url = STIX_URL.format(version=args.version)
    print(f"Downloading {url} …")
    with urllib.request.urlopen(url) as response:
        bundle = json.load(response)

    lookup = build_lookup(bundle, args.version)
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"enterprise-attack-{args.version}-lookup.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(lookup, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print(f"✓ Wrote {os.path.relpath(out)} ({len(lookup['tactics'])} tactics, {len(lookup['techniques'])} techniques)")


if __name__ == "__main__":
    main()
