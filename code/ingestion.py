"""
ingestion.py - Data Ingestion Module for Ghost Data Still Exists (HackerRank Orchestrate).

Role: Data Engineer
Responsible for understanding, locating, validating, and loading all input datasets using Pandas.

Datasets loaded:
1. deletion_requests.csv (518 evaluation requests)
2. sample_deletion_requests.csv (32 sample requests)
3. sample_output.csv (32 sample expected outputs)
4. user_identities.csv (850 current user identity records)
5. user_audit_log.csv (306 historical identity change records)
6. system_activity.csv (4,011 operational activity events)
7. deletion_rules.csv (15 policy rules for data categories and actions)
8. evidence_files.csv (94 manifest entries under dataset/evidence/)
9. output.csv (Submission template for 518 cases)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ingestion")


# ---------------------------------------------------------------------------
# Path Resolution
# ---------------------------------------------------------------------------

def resolve_dataset_dir(custom_path: Optional[Union[str, Path]] = None) -> Path:
    """
    Locates and returns the absolute Path to the 'dataset' directory.
    Searches custom path, environment variables, relative directories, and workspace roots.
    """
    if custom_path:
        p = Path(custom_path).resolve()
        if p.is_dir() and (p / "deletion_requests.csv").exists():
            return p
        if (p / "dataset").is_dir() and (p / "dataset" / "deletion_requests.csv").exists():
            return (p / "dataset").resolve()

    for env_var in ("DATASET_DIR", "GHOSTPRINT_DATASET_DIR", "CHALLENGE_DATASET_DIR"):
        val = os.environ.get(env_var)
        if val:
            p = Path(val).resolve()
            if p.is_dir() and (p / "deletion_requests.csv").exists():
                return p

    # Candidate locations relative to this file or current working directory
    file_dir = Path(__file__).resolve().parent
    cwd = Path.cwd().resolve()

    candidates = [
        file_dir / "dataset",
        file_dir.parent / "dataset",
        file_dir / "Ghost-Print" / "dataset",
        file_dir.parent / "Ghost-Print" / "dataset",
        cwd / "dataset",
        cwd / "Ghost-Print" / "dataset",
        cwd.parent / "dataset",
        Path("C:/Users/Lenovo/project/Ghost-Print/dataset"),
    ]

    for candidate in candidates:
        if candidate.is_dir() and (candidate / "deletion_requests.csv").exists():
            return candidate.resolve()

    raise FileNotFoundError(
        "Could not locate the 'dataset' directory containing deletion_requests.csv. "
        "Please provide the path via resolve_dataset_dir(path) or DATASET_DIR environment variable."
    )


# ---------------------------------------------------------------------------
# Evidence File Model & Manifest
# ---------------------------------------------------------------------------

@dataclass
class EvidenceFile:
    """
    Represents an evidence file referenced in evidence_files.csv.
    Provides safe file reading utilities for logs, JSON, SQL, text, and binary assets.
    """
    file_id: str
    file_path: str
    origin: str
    captured_at: str
    full_path: Path
    exists: bool = False
    file_type: str = "unknown"
    file_size_bytes: int = 0

    def __post_init__(self):
        if self.full_path.exists():
            self.exists = True
            try:
                self.file_size_bytes = self.full_path.stat().st_size
            except OSError:
                self.file_size_bytes = 0
        ext = self.full_path.suffix.lower()
        if ext in (".json",):
            self.file_type = "json"
        elif ext in (".log",):
            self.file_type = "log"
        elif ext in (".sql",):
            self.file_type = "sql"
        elif ext in (".txt",):
            self.file_type = "text"
        elif ext in (".png", ".jpg", ".jpeg"):
            self.file_type = "image"
        elif ext in (".pdf",):
            self.file_type = "pdf"
        else:
            self.file_type = ext.lstrip(".") or "unknown"

    def read_text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """Reads file contents as text."""
        if not self.exists:
            raise FileNotFoundError(f"Evidence file not found on disk: {self.full_path}")
        return self.full_path.read_text(encoding=encoding, errors=errors)

    def read_json(self) -> Any:
        """Parses and returns JSON content."""
        text = self.read_text()
        return json.loads(text)

    def read_bytes(self) -> bytes:
        """Reads file contents as binary bytes."""
        if not self.exists:
            raise FileNotFoundError(f"Evidence file not found on disk: {self.full_path}")
        return self.full_path.read_bytes()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_id": self.file_id,
            "file_path": self.file_path,
            "origin": self.origin,
            "captured_at": self.captured_at,
            "full_path": str(self.full_path),
            "exists": self.exists,
            "file_type": self.file_type,
            "file_size_bytes": self.file_size_bytes,
        }


class EvidenceManifest:
    """
    Manages the collection of evidence files registered in evidence_files.csv.
    """

    def __init__(self, files: List[EvidenceFile]):
        self._files_list = files
        self._by_id: Dict[str, EvidenceFile] = {f.file_id: f for f in files}

    def __len__(self) -> int:
        return len(self._files_list)

    def __iter__(self):
        return iter(self._files_list)

    def get(self, file_id: str) -> Optional[EvidenceFile]:
        """Retrieves an EvidenceFile by its file_id (e.g. 'evidence_01')."""
        return self._by_id.get(file_id)

    def list_files(self) -> List[EvidenceFile]:
        """Returns all evidence files."""
        return list(self._files_list)

    def filter_by_origin(self, origin: str) -> List[EvidenceFile]:
        """Filters evidence files by source origin system."""
        return [f for f in self._files_list if f.origin == origin]

    def filter_by_type(self, file_type: str) -> List[EvidenceFile]:
        """Filters evidence files by extension/type ('sql', 'log', 'json', etc.)."""
        return [f for f in self._files_list if f.file_type.lower() == file_type.lower()]

    def filter_captured_before(self, cutoff_iso: str) -> List[EvidenceFile]:
        """
        Filters evidence files captured at or before cutoff_iso.
        Enforces the audit_at constraint (ignoring evidence created after cutoff).
        """
        return [f for f in self._files_list if f.captured_at <= cutoff_iso]

    def to_dataframe(self) -> pd.DataFrame:
        """Returns evidence manifest as a Pandas DataFrame."""
        return pd.DataFrame([f.to_dict() for f in self._files_list])


# ---------------------------------------------------------------------------
# Individual CSV Loaders (Using Pandas)
# ---------------------------------------------------------------------------

def load_deletion_requests(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads deletion_requests.csv (518 evaluation cases)."""
    p = resolve_dataset_dir(dataset_dir) / "deletion_requests.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded deletion_requests: %d rows", len(df))
    return df


def load_sample_deletion_requests(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads sample_deletion_requests.csv (32 public sample cases)."""
    p = resolve_dataset_dir(dataset_dir) / "sample_deletion_requests.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded sample_deletion_requests: %d rows", len(df))
    return df


def load_sample_output(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads sample_output.csv (ground truth for sample cases)."""
    p = resolve_dataset_dir(dataset_dir) / "sample_output.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded sample_output: %d rows", len(df))
    return df


def load_user_identities(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads user_identities.csv (current user snapshot)."""
    p = resolve_dataset_dir(dataset_dir) / "user_identities.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded user_identities: %d rows", len(df))
    return df


def load_user_audit_log(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads user_audit_log.csv (historical identity change history)."""
    p = resolve_dataset_dir(dataset_dir) / "user_audit_log.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded user_audit_log: %d rows", len(df))
    return df


def load_system_activity(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads system_activity.csv (global activity stream)."""
    p = resolve_dataset_dir(dataset_dir) / "system_activity.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded system_activity: %d rows", len(df))
    return df


def load_deletion_rules(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads deletion_rules.csv (policy requirements per data category)."""
    p = resolve_dataset_dir(dataset_dir) / "deletion_rules.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded deletion_rules: %d rows", len(df))
    return df


def load_evidence_files(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads evidence_files.csv manifest."""
    p = resolve_dataset_dir(dataset_dir) / "evidence_files.csv"
    df = pd.read_csv(p, encoding="utf-8")
    logger.debug("Loaded evidence_files: %d rows", len(df))
    return df


def load_output_template(dataset_dir: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Loads output.csv schema/template."""
    p = resolve_dataset_dir(dataset_dir) / "output.csv"
    df = pd.read_csv(p, encoding="utf-8")
    return df


# ---------------------------------------------------------------------------
# DataIngestor: Common Data Access Container
# ---------------------------------------------------------------------------

class DataIngestor:
    """
    Central Data Ingestion controller that loads, caches, and provides structured access
    to all challenge datasets and evidence manifests.
    """

    def __init__(self, dataset_dir: Optional[Union[str, Path]] = None):
        self.dataset_dir = resolve_dataset_dir(dataset_dir)
        logger.info("Initializing DataIngestor with dataset at: %s", self.dataset_dir)

        # Lazy or eagerly cached dataframes
        self._user_identities: Optional[pd.DataFrame] = None
        self._user_audit_log: Optional[pd.DataFrame] = None
        self._deletion_requests: Optional[pd.DataFrame] = None
        self._sample_requests: Optional[pd.DataFrame] = None
        self._sample_output: Optional[pd.DataFrame] = None
        self._system_activity: Optional[pd.DataFrame] = None
        self._deletion_rules: Optional[pd.DataFrame] = None
        self._evidence_files_df: Optional[pd.DataFrame] = None
        self._evidence_manifest: Optional[EvidenceManifest] = None

    def load_all(self) -> Dict[str, pd.DataFrame]:
        """Loads and caches all CSV datasets into memory."""
        logger.info("Loading all CSV files using Pandas...")
        return {
            "user_identities": self.user_identities,
            "user_audit_log": self.user_audit_log,
            "deletion_requests": self.deletion_requests,
            "sample_deletion_requests": self.sample_requests,
            "sample_output": self.sample_output,
            "system_activity": self.system_activity,
            "deletion_rules": self.deletion_rules,
            "evidence_files": self.evidence_files,
        }

    @property
    def user_identities(self) -> pd.DataFrame:
        if self._user_identities is None:
            self._user_identities = load_user_identities(self.dataset_dir)
        return self._user_identities

    @property
    def user_audit_log(self) -> pd.DataFrame:
        if self._user_audit_log is None:
            self._user_audit_log = load_user_audit_log(self.dataset_dir)
        return self._user_audit_log

    @property
    def deletion_requests(self) -> pd.DataFrame:
        if self._deletion_requests is None:
            self._deletion_requests = load_deletion_requests(self.dataset_dir)
        return self._deletion_requests

    @property
    def sample_requests(self) -> pd.DataFrame:
        if self._sample_requests is None:
            self._sample_requests = load_sample_deletion_requests(self.dataset_dir)
        return self._sample_requests

    @property
    def sample_output(self) -> pd.DataFrame:
        if self._sample_output is None:
            self._sample_output = load_sample_output(self.dataset_dir)
        return self._sample_output

    @property
    def system_activity(self) -> pd.DataFrame:
        if self._system_activity is None:
            self._system_activity = load_system_activity(self.dataset_dir)
        return self._system_activity

    @property
    def deletion_rules(self) -> pd.DataFrame:
        if self._deletion_rules is None:
            self._deletion_rules = load_deletion_rules(self.dataset_dir)
        return self._deletion_rules

    @property
    def evidence_files(self) -> pd.DataFrame:
        if self._evidence_files_df is None:
            self._evidence_files_df = load_evidence_files(self.dataset_dir)
        return self._evidence_files_df

    @property
    def evidence_manifest(self) -> EvidenceManifest:
        """Builds and returns the EvidenceManifest object."""
        if self._evidence_manifest is None:
            df = self.evidence_files
            evidence_root = self.dataset_dir

            file_objects: List[EvidenceFile] = []
            for _, row in df.iterrows():
                rel_path = str(row["file_path"]).replace("\\", "/")
                # File path in manifest is typically 'evidence/databases/...'
                full_path = (evidence_root / rel_path).resolve()
                if not full_path.exists():
                    # Check if relative without 'evidence/' prefix
                    trimmed = rel_path.replace("evidence/", "")
                    alt_path = (evidence_root / "evidence" / trimmed).resolve()
                    if alt_path.exists():
                        full_path = alt_path

                ef = EvidenceFile(
                    file_id=str(row["file_id"]),
                    file_path=rel_path,
                    origin=str(row["origin"]),
                    captured_at=str(row["captured_at"]),
                    full_path=full_path,
                )
                file_objects.append(ef)

            self._evidence_manifest = EvidenceManifest(file_objects)
        return self._evidence_manifest

    def get_evidence_file(self, file_id: str) -> Optional[EvidenceFile]:
        """Convenience method to retrieve an EvidenceFile by ID."""
        return self.evidence_manifest.get(file_id)

    def summary(self) -> Dict[str, Any]:
        """Returns summary statistics for all loaded datasets."""
        self.load_all()
        manifest = self.evidence_manifest
        existing_files = sum(1 for f in manifest if f.exists)

        return {
            "dataset_dir": str(self.dataset_dir),
            "user_identities_count": len(self.user_identities),
            "user_audit_log_count": len(self.user_audit_log),
            "deletion_requests_count": len(self.deletion_requests),
            "sample_requests_count": len(self.sample_requests),
            "sample_output_count": len(self.sample_output),
            "system_activity_count": len(self.system_activity),
            "deletion_rules_count": len(self.deletion_rules),
            "evidence_files_manifest_count": len(self.evidence_files),
            "evidence_files_on_disk_count": f"{existing_files}/{len(manifest)}",
        }


# ---------------------------------------------------------------------------
# CLI / Self-Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Ghost-Print Data Ingestion Pipeline (Pandas)")
    print("=" * 60)

    ingestor = DataIngestor()
    summary = ingestor.summary()

    for k, v in summary.items():
        print(f"  {k:30}: {v}")

    print("\nEvidence Files Breakdown by Type:")
    type_counts: Dict[str, int] = {}
    for f in ingestor.evidence_manifest:
        type_counts[f.file_type] = type_counts.get(f.file_type, 0) + 1
    for ftype, count in sorted(type_counts.items()):
        print(f"  - {ftype:10}: {count} files")

    print("\nData ingestion verified successfully.")

