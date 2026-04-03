"""Unit tests for get_techniques_data_sources_from_group.py"""

import csv
import importlib
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import the main module (underscores in filename are importable)
sys.path.insert(0, str(Path(__file__).parent.parent))
main = importlib.import_module("get_techniques_data_sources_from_group")


def _make_group(name: str, aliases: list[str] | None = None, stix_id: str = "intrusion-set--abc123"):
    group = MagicMock()
    group.get = lambda key, default=None: {
        "name": name,
        "aliases": aliases or [],
        "id": stix_id,
    }.get(key, default)
    return group


def _make_technique(name: str, data_sources: list[str] | None = None):
    tech = MagicMock()
    tech.get = lambda key, default=None: {"name": name}.get(key, default)
    tech.x_mitre_data_sources = data_sources
    return tech


class TestFindGroup:
    def test_match_by_name(self):
        mitre = MagicMock()
        mitre.get_groups.return_value = [_make_group("APT33", ["Elfin"])]
        result = main.find_group(mitre, "APT33")
        assert result is not None

    def test_match_by_alias(self):
        mitre = MagicMock()
        mitre.get_groups.return_value = [_make_group("APT33", ["Elfin"])]
        result = main.find_group(mitre, "elfin")  # case-insensitive
        assert result is not None

    def test_no_match(self):
        mitre = MagicMock()
        mitre.get_groups.return_value = [_make_group("APT33")]
        result = main.find_group(mitre, "UnknownGroup")
        assert result is None


class TestListGroups:
    def test_sorted(self):
        mitre = MagicMock()
        mitre.get_groups.return_value = [_make_group("Lazarus"), _make_group("APT33")]
        result = main.list_groups(mitre)
        assert result == ["APT33", "Lazarus"]


class TestGetTechniquesDatasources:
    def test_returns_data_sources(self):
        mitre = MagicMock()
        group = _make_group("APT33", stix_id="intrusion-set--abc")
        tech = _make_technique("Phishing", ["Email Gateway: Email Content"])
        mitre.get_techniques_used_by_group.return_value = [{"object": tech}]

        result = main.get_techniques_datasources(mitre, group)
        assert result == {"Phishing": ["Email Gateway: Email Content"]}

    def test_fallback_na_when_no_sources(self):
        mitre = MagicMock()
        group = _make_group("APT33", stix_id="intrusion-set--abc")
        tech = _make_technique("SomeTechnique", data_sources=None)
        mitre.get_techniques_used_by_group.return_value = [{"object": tech}]

        result = main.get_techniques_datasources(mitre, group)
        assert result == {"SomeTechnique": ["N/A"]}

    def test_skips_none_object(self):
        mitre = MagicMock()
        group = _make_group("APT33", stix_id="intrusion-set--abc")
        mitre.get_techniques_used_by_group.return_value = [{"object": None}]

        result = main.get_techniques_datasources(mitre, group)
        assert result == {}

    def test_handles_exception(self):
        mitre = MagicMock()
        group = _make_group("APT33", stix_id="intrusion-set--abc")
        mitre.get_techniques_used_by_group.side_effect = Exception("network error")

        result = main.get_techniques_datasources(mitre, group)
        assert result == {}


class TestExportCsv:
    def test_writes_csv(self):
        data = {"Phishing": ["Email Gateway", "Network Traffic"]}
        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "out.csv")
            main.export_csv(data, output)
            with open(output, newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))
        assert rows[0] == ["technique", "data source"]
        assert ["Phishing", "Email Gateway"] in rows
        assert ["Phishing", "Network Traffic"] in rows

    def test_creates_parent_directories(self):
        data = {"T1": ["DS1"]}
        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "subdir" / "out.csv")
            main.export_csv(data, output)
            assert Path(output).exists()
