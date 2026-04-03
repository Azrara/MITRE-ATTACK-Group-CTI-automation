#!/usr/bin/env python3
"""
MITRE ATT&CK Group CTI Automation

Retrieves all techniques and associated data sources for a specified
MITRE ATT&CK threat group and exports results to CSV.

Compatible with MITRE ATT&CK v18+ via the mitreattack-python library.
Data is fetched from the official MITRE ATT&CK STIX repository on GitHub.

Usage:
    python3 get_techniques_data_sources_from_group.py --group APT33
    python3 get_techniques_data_sources_from_group.py --group APT33 --output results.csv
    python3 get_techniques_data_sources_from_group.py --list-groups
"""

import argparse
import csv
import logging
import sys
import urllib.request
from pathlib import Path

from mitreattack.stix20 import MitreAttackData

# Latest ATT&CK enterprise STIX data (v18.1)
STIX_DATA_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "mitre-attack" / "enterprise-attack.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def load_attack_data(source: str) -> MitreAttackData:
    """Load ATT&CK STIX data from a local file path or a remote URL.

    Remote files are downloaded and cached at DEFAULT_CACHE_PATH.
    """
    if source.startswith(("http://", "https://")):
        log.info("Downloading ATT&CK STIX data...")
        DEFAULT_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            urllib.request.urlretrieve(source, DEFAULT_CACHE_PATH)
        except Exception as exc:
            raise RuntimeError(f"Failed to download STIX data: {exc}") from exc
        source = str(DEFAULT_CACHE_PATH)

    return MitreAttackData(source)


def find_group(mitre: MitreAttackData, name: str):
    """Return the first group whose name or alias matches (case-insensitive).

    Returns None if no match is found.
    """
    for group in mitre.get_groups():
        candidates = [group.get("name", "")] + list(group.get("aliases") or [])
        if name.lower() in [c.lower() for c in candidates if c]:
            return group
    return None


def list_groups(mitre: MitreAttackData) -> list[str]:
    """Return a sorted list of all known group names."""
    return sorted(g.get("name", "") for g in mitre.get_groups())


def get_techniques_datasources(
    mitre: MitreAttackData, group
) -> dict[str, list[str]]:
    """Return a mapping of technique name -> list of data sources for the group.

    Techniques with no data sources are recorded with ["N/A"].
    """
    result: dict[str, list[str]] = {}
    group_id = group.get("id")

    try:
        techniques_with_rels = mitre.get_techniques_used_by_group(group_id)
    except Exception as exc:
        log.error("Failed to retrieve techniques: %s", exc)
        return result

    for item in techniques_with_rels:
        technique = item.get("object")
        if technique is None:
            continue
        name = technique.get("name", "Unknown")
        sources = list(getattr(technique, "x_mitre_data_sources", None) or [])
        result[name] = sources if sources else ["N/A"]

    return result


def export_csv(data: dict[str, list[str]], output: str) -> None:
    """Write technique/data-source pairs to a CSV file."""
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", newline="", encoding="utf-8") as fd:
        writer = csv.writer(fd)
        writer.writerow(["technique", "data source"])
        for technique, sources in data.items():
            for source in sources:
                writer.writerow([technique, source])

    log.info("Saved %d techniques to %s", len(data), out_path.resolve())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Retrieve MITRE ATT&CK techniques and data sources for a threat group."
    )
    parser.add_argument(
        "--group", "-g",
        type=str,
        help="ATT&CK group name or alias (e.g. APT33)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="techniques_datasource.csv",
        help="Output CSV file path (default: techniques_datasource.csv)",
    )
    parser.add_argument(
        "--stix-data",
        type=str,
        default=STIX_DATA_URL,
        help="Local path or URL to ATT&CK STIX JSON (default: latest from GitHub)",
    )
    parser.add_argument(
        "--list-groups",
        action="store_true",
        help="Print all known group names and exit",
    )
    args = parser.parse_args()

    if not args.list_groups and not args.group:
        parser.error("--group / -g is required (or use --list-groups)")

    log.info("Loading MITRE ATT&CK data (v18+)...")
    try:
        mitre = load_attack_data(args.stix_data)
    except Exception as exc:
        log.error("%s", exc)
        return 1

    if args.list_groups:
        for name in list_groups(mitre):
            print(name)
        return 0

    group = find_group(mitre, args.group)
    if group is None:
        log.error(
            "Group '%s' not found. Use --list-groups to see available groups.",
            args.group,
        )
        return 1

    log.info("Found group: %s", group.get("name"))
    data = get_techniques_datasources(mitre, group)

    if not data:
        log.warning("No techniques found for group '%s'.", args.group)
        return 0

    export_csv(data, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
