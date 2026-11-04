"""
identity.py - Identity Resolution Module for Ghost Data Still Exists (HackerRank Orchestrate).

Role: Data Engineer
Responsible for:
1. Linking current user identities (user_identities.csv) with historical audit changes (user_audit_log.csv).
2. Reconstructing full chronological identity history (old and new emails, phones, hashes).
3. Providing clean, strongly-typed common data structures (UserIdentity, DeletionRequest, IdentityAuditEntry)
   for downstream agents and team members (evidence scanners, rule engine, remediation planner).
4. Deliverable: Given a deletion request, return the correct user and their known identifiers.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pandas as pd

try:
    from ingestion import DataIngestor, resolve_dataset_dir
except ImportError:
    # If running from another directory or imported relatively
    from .ingestion import DataIngestor, resolve_dataset_dir

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("identity")


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def normalize_email(email: Optional[str]) -> str:
    """Normalizes an email address (stripped and lowercased)."""
    if not email or pd.isna(email):
        return ""
    return str(email).strip().lower()


def compute_sha256(value: str) -> str:
    """Computes lowercase hex SHA-256 hash of a string."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def normalize_phone(phone: Optional[str]) -> str:
    """Normalizes a phone number by stripping whitespace and redundant punctuation."""
    if not phone or pd.isna(phone):
        return ""
    return str(phone).strip()


def extract_phone_digits(phone: str) -> str:
    """Extracts digits only for loose matching across various phone formats."""
    return re.sub(r"\D", "", phone)


# ---------------------------------------------------------------------------
# Common Data Structures
# ---------------------------------------------------------------------------

@dataclass
class IdentityAuditEntry:
    """
    Represents an audit entry from user_audit_log.csv tracking an identity field update.
    """
    audit_id: str
    user_id: str
    event_time: str
    field_name: str  # 'email', 'phone', 'email_hash'
    old_value: str
    new_value: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "audit_id": self.audit_id,
            "user_id": self.user_id,
            "event_time": self.event_time,
            "field_name": self.field_name,
            "old_value": self.old_value,
            "new_value": self.new_value,
        }


@dataclass
class UserIdentity:
    """
    Common Data Structure for a user's unified identity profile.
    Combines current state and historical changes into a single comprehensive model.
    """
    user_id: str
    name: str
    current_email: str
    current_phone: str
    current_email_hash: str
    updated_at: str

    historical_emails: List[str] = field(default_factory=list)
    historical_phones: List[str] = field(default_factory=list)
    historical_email_hashes: List[str] = field(default_factory=list)

    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_email_hashes: Set[str] = field(default_factory=set)

    audit_history: List[IdentityAuditEntry] = field(default_factory=list)

    def __post_init__(self):
        # Ensure sets include current values
        if self.current_email:
            self.all_emails.add(self.current_email)
        for e in self.historical_emails:
            if e:
                self.all_emails.add(e)

        if self.current_phone:
            self.all_phones.add(self.current_phone)
        for p in self.historical_phones:
            if p:
                self.all_phones.add(p)

        if self.current_email_hash:
            self.all_email_hashes.add(self.current_email_hash)
        for h in self.historical_email_hashes:
            if h:
                self.all_email_hashes.add(h)

    @property
    def has_historical_changes(self) -> bool:
        """True if this user has any recorded audit history."""
        return len(self.audit_history) > 0

    @property
    def has_email_changes(self) -> bool:
        """True if the user had email changes in history."""
        return len(self.historical_emails) > 0

    def get_search_terms(self) -> Set[str]:
        """
        Returns a set of search strings for scanning evidence (logs, SQL dumps, JSON files, etc.).
        Includes user_id, full name, all emails, all phones, and all hashes.
        """
        terms: Set[str] = {self.user_id}
        if self.name and self.name.strip():
            terms.add(self.name.strip())
        for e in self.all_emails:
            terms.add(e)
        for p in self.all_phones:
            terms.add(p)
            digits = extract_phone_digits(p)
            if len(digits) >= 7:
                terms.add(digits)
        for h in self.all_email_hashes:
            terms.add(h)
        return terms

    def matches_identifier(self, identifier: str) -> bool:
        """
        Checks whether a given string corresponds to any known identifier of this user.
        """
        if not identifier:
            return False
        norm = identifier.strip().lower()

        if norm == self.user_id.lower():
            return True
        if self.name and norm == self.name.strip().lower():
            return True
        if norm in {e.lower() for e in self.all_emails}:
            return True
        if norm in {h.lower() for h in self.all_email_hashes}:
            return True
        if norm in {p.lower() for p in self.all_phones}:
            return True

        # Check phone digits
        digits = extract_phone_digits(identifier)
        if digits and len(digits) >= 7:
            for p in self.all_phones:
                if digits == extract_phone_digits(p):
                    return True

        return False

    def is_historical_email(self, email: str) -> bool:
        """Returns True if the email is a historical email and not the current one."""
        norm = normalize_email(email)
        return norm != self.current_email and norm in {e.lower() for e in self.historical_emails}

    def to_dict(self) -> Dict[str, Any]:
        """Full serialization of user identity."""
        return {
            "user_id": self.user_id,
            "name": self.name,
            "current_email": self.current_email,
            "current_phone": self.current_phone,
            "current_email_hash": self.current_email_hash,
            "updated_at": self.updated_at,
            "historical_emails": list(self.historical_emails),
            "historical_phones": list(self.historical_phones),
            "historical_email_hashes": list(self.historical_email_hashes),
            "all_emails": sorted(list(self.all_emails)),
            "all_phones": sorted(list(self.all_phones)),
            "all_email_hashes": sorted(list(self.all_email_hashes)),
            "audit_history": [a.to_dict() for a in self.audit_history],
        }

    def to_summary_dict(self) -> Dict[str, Any]:
        """Concise summary for logging and downstream reports."""
        return {
            "user_id": self.user_id,
            "name": self.name,
            "current_email": self.current_email,
            "historical_emails_count": len(self.historical_emails),
            "historical_emails": self.historical_emails,
            "all_emails_count": len(self.all_emails),
            "all_phones_count": len(self.all_phones),
            "all_hashes_count": len(self.all_email_hashes),
            "audit_entries_count": len(self.audit_history),
        }

    def __repr__(self) -> str:
        hist_info = f", hist_emails={len(self.historical_emails)}" if self.historical_emails else ""
        return f"<UserIdentity {self.user_id}: {self.name} <{self.current_email}>{hist_info}>"


@dataclass
class DeletionRequest:
    """
    Represents a deletion request from deletion_requests.csv or sample_deletion_requests.csv.
    """
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str
    is_sample: bool = False

    @property
    def normalized_email(self) -> str:
        return normalize_email(self.email)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "email": self.email,
            "requested_at": self.requested_at,
            "reported_status": self.reported_status,
            "reported_at": self.reported_at,
            "audit_at": self.audit_at,
            "request_text": self.request_text,
            "is_sample": self.is_sample,
        }


# ---------------------------------------------------------------------------
# Identity Resolver
# ---------------------------------------------------------------------------

class IdentityResolver:
    """
    Builds the unified identity graph connecting current identities, historical audit logs,
    and deletion requests. Provides fast O(1) identity lookups and query resolution.
    """

    def __init__(self, ingestor_or_dir: Optional[Union[DataIngestor, str, Path]] = None):
        if isinstance(ingestor_or_dir, DataIngestor):
            self.ingestor = ingestor_or_dir
        else:
            self.ingestor = DataIngestor(ingestor_or_dir)

        self._users_by_id: Dict[str, UserIdentity] = {}
        self._email_to_user_id: Dict[str, str] = {}
        self._hash_to_user_id: Dict[str, str] = {}
        self._phone_to_user_id: Dict[str, str] = {}
        self._requests_by_case_id: Dict[str, DeletionRequest] = {}

        self._build_identity_graph()
        self._index_requests()

    def _build_identity_graph(self):
        """
        Parses user_identities.csv and user_audit_log.csv, linking historical changes
        to each user's profile and indexing all identifiers.
        """
        logger.info("Building identity graph from user identities and audit logs...")
        identities_df = self.ingestor.user_identities
        audit_df = self.ingestor.user_audit_log

        # 1. Initialize user profiles from user_identities.csv
        for _, row in identities_df.iterrows():
            uid = str(row["user_id"]).strip()
            name = str(row["name"]).strip()
            curr_email = normalize_email(row["email"])
            curr_phone = normalize_phone(row["phone"])
            curr_hash = str(row["email_hash"]).strip().lower()
            updated_at = str(row["updated_at"]).strip()

            # Ensure current email hash is valid
            if not curr_hash and curr_email:
                curr_hash = compute_sha256(curr_email)

            user = UserIdentity(
                user_id=uid,
                name=name,
                current_email=curr_email,
                current_phone=curr_phone,
                current_email_hash=curr_hash,
                updated_at=updated_at,
            )
            self._users_by_id[uid] = user

        # 2. Process user_audit_log.csv sorted chronologically
        # Sort by event_time to preserve history order
        sorted_audit = audit_df.copy()
        if "event_time" in sorted_audit.columns:
            sorted_audit["_sort_time"] = pd.to_datetime(sorted_audit["event_time"], errors="coerce")
            sorted_audit = sorted_audit.sort_values("_sort_time")

        for _, row in sorted_audit.iterrows():
            uid = str(row["user_id"]).strip()
            user = self._users_by_id.get(uid)
            if not user:
                continue

            audit_entry = IdentityAuditEntry(
                audit_id=str(row["audit_id"]).strip(),
                user_id=uid,
                event_time=str(row["event_time"]).strip(),
                field_name=str(row["field_name"]).strip(),
                old_value=str(row["old_value"]).strip() if pd.notna(row["old_value"]) else "",
                new_value=str(row["new_value"]).strip() if pd.notna(row["new_value"]) else "",
            )
            user.audit_history.append(audit_entry)

            field_name = audit_entry.field_name.lower()
            old_val = audit_entry.old_value
            new_val = audit_entry.new_value

            if field_name == "email":
                if old_val:
                    norm_old = normalize_email(old_val)
                    if norm_old and norm_old not in user.historical_emails:
                        user.historical_emails.append(norm_old)
                        user.all_emails.add(norm_old)
                        # Also compute and add hash for old email
                        old_hash = compute_sha256(norm_old)
                        if old_hash not in user.historical_email_hashes:
                            user.historical_email_hashes.append(old_hash)
                            user.all_email_hashes.add(old_hash)
                if new_val:
                    norm_new = normalize_email(new_val)
                    if norm_new:
                        user.all_emails.add(norm_new)

            elif field_name == "phone":
                if old_val:
                    norm_old_p = normalize_phone(old_val)
                    if norm_old_p and norm_old_p not in user.historical_phones:
                        user.historical_phones.append(norm_old_p)
                        user.all_phones.add(norm_old_p)
                if new_val:
                    norm_new_p = normalize_phone(new_val)
                    if norm_new_p:
                        user.all_phones.add(norm_new_p)

            elif field_name == "email_hash":
                if old_val:
                    norm_h = old_val.strip().lower()
                    if norm_h and norm_h not in user.historical_email_hashes:
                        user.historical_email_hashes.append(norm_h)
                        user.all_email_hashes.add(norm_h)
                if new_val:
                    norm_h = new_val.strip().lower()
                    if norm_h:
                        user.all_email_hashes.add(norm_h)

        # 3. Build fast inverted lookup indexes
        for uid, user in self._users_by_id.items():
            for e in user.all_emails:
                self._email_to_user_id[e.lower()] = uid
            for h in user.all_email_hashes:
                self._hash_to_user_id[h.lower()] = uid
            for p in user.all_phones:
                self._phone_to_user_id[p] = uid
                digits = extract_phone_digits(p)
                if digits and len(digits) >= 7:
                    self._phone_to_user_id[digits] = uid

        logger.info(
            "Identity graph built: %d users, %d indexed emails, %d hashes, %d phones",
            len(self._users_by_id),
            len(self._email_to_user_id),
            len(self._hash_to_user_id),
            len(self._phone_to_user_id),
        )

    def _index_requests(self):
        """Indexes both evaluation and sample requests by case_id."""
        for is_sample, df in [(False, self.ingestor.deletion_requests), (True, self.ingestor.sample_requests)]:
            for _, r in df.iterrows():
                cid = str(r["case_id"]).strip()
                req = DeletionRequest(
                    case_id=cid,
                    email=str(r["email"]).strip(),
                    requested_at=str(r["requested_at"]).strip(),
                    reported_status=str(r["reported_status"]).strip(),
                    reported_at=str(r["reported_at"]).strip(),
                    audit_at=str(r["audit_at"]).strip(),
                    request_text=str(r["request_text"]) if pd.notna(r["request_text"]) else "",
                    is_sample=is_sample,
                )
                self._requests_by_case_id[cid] = req

    # -----------------------------------------------------------------------
    # Core Deliverable & Resolution Methods
    # -----------------------------------------------------------------------

    def resolve_user(
        self, query: Union[str, Dict[str, Any], pd.Series, DeletionRequest]
    ) -> Optional[UserIdentity]:
        """
        DELIVERABLE METHOD:
        Given a deletion request (case_id, email, request dict/Series, or DeletionRequest),
        returns the correct user profile with all their known current and historical identifiers.

        Args:
            query: Can be:
                - A case_id (e.g. 'case_01', 'case_33')
                - An email string (current or historical)
                - A user_id string (e.g. 'user_01')
                - A SHA-256 email hash string
                - A phone string
                - A deletion request dict / pd.Series containing 'email' or 'case_id'
                - A DeletionRequest instance

        Returns:
            The resolved UserIdentity, or None if no match found.
        """
        if query is None:
            return None

        # Case 1: DeletionRequest dataclass
        if isinstance(query, DeletionRequest):
            return self.get_user_by_email(query.email)

        # Case 2: Dict or Pandas Series
        if isinstance(query, (dict, pd.Series)):
            if "case_id" in query and str(query["case_id"]) in self._requests_by_case_id:
                req = self._requests_by_case_id[str(query["case_id"])]
                return self.get_user_by_email(req.email)
            if "email" in query and query["email"]:
                return self.get_user_by_email(str(query["email"]))
            if "user_id" in query and query["user_id"]:
                return self.get_user_by_id(str(query["user_id"]))

        # Case 3: String query
        if isinstance(query, str):
            q_clean = query.strip()
            # 3a. Direct case_id lookup
            if q_clean in self._requests_by_case_id:
                return self.get_user_by_email(self._requests_by_case_id[q_clean].email)
            # 3b. Direct user_id lookup
            if q_clean in self._users_by_id:
                return self._users_by_id[q_clean]
            # 3c. Email lookup (current or historical)
            by_email = self.get_user_by_email(q_clean)
            if by_email:
                return by_email
            # 3d. Hash lookup
            by_hash = self.get_user_by_hash(q_clean)
            if by_hash:
                return by_hash
            # 3e. Phone lookup
            by_phone = self.get_user_by_phone(q_clean)
            if by_phone:
                return by_phone

        return None

    def get_user_by_id(self, user_id: str) -> Optional[UserIdentity]:
        """Looks up a user by exact user_id (e.g. 'user_01')."""
        return self._users_by_id.get(user_id.strip())

    def get_user_by_email(self, email: str) -> Optional[UserIdentity]:
        """
        Looks up a user by email, searching across both current and historical emails.
        """
        norm = normalize_email(email)
        uid = self._email_to_user_id.get(norm)
        if uid:
            return self._users_by_id.get(uid)
        return None

    def get_user_by_hash(self, email_hash: str) -> Optional[UserIdentity]:
        """Looks up a user by current or historical SHA-256 email hash."""
        h = email_hash.strip().lower()
        uid = self._hash_to_user_id.get(h)
        if uid:
            return self._users_by_id.get(uid)
        return None

    def get_user_by_phone(self, phone: str) -> Optional[UserIdentity]:
        """Looks up a user by phone string or phone digits."""
        p = normalize_phone(phone)
        uid = self._phone_to_user_id.get(p)
        if not uid:
            digits = extract_phone_digits(p)
            uid = self._phone_to_user_id.get(digits)
        if uid:
            return self._users_by_id.get(uid)
        return None

    def get_request_by_case_id(self, case_id: str) -> Optional[DeletionRequest]:
        """Retrieves a DeletionRequest by its case_id."""
        return self._requests_by_case_id.get(case_id.strip())

    def resolve_case(
        self, case_id: str
    ) -> Tuple[Optional[DeletionRequest], Optional[UserIdentity]]:
        """
        Returns both the DeletionRequest and the resolved UserIdentity for a case_id.
        """
        req = self.get_request_by_case_id(case_id)
        if not req:
            return None, None
        user = self.get_user_by_email(req.email)
        return req, user

    def resolve_all_requests(
        self, requests_df: Optional[pd.DataFrame] = None
    ) -> pd.DataFrame:
        """
        Resolves every request in the provided DataFrame (or deletion_requests.csv by default),
        returning an enriched DataFrame mapping each case to its resolved identity details.
        """
        if requests_df is None:
            requests_df = self.ingestor.deletion_requests

        rows: List[Dict[str, Any]] = []
        for _, r in requests_df.iterrows():
            cid = str(r["case_id"]).strip()
            req_email = str(r["email"]).strip()
            user = self.resolve_user(req_email)

            if user:
                is_historical = user.is_historical_email(req_email)
                rows.append({
                    "case_id": cid,
                    "request_email": req_email,
                    "email_type": "HISTORICAL" if is_historical else "CURRENT",
                    "user_id": user.user_id,
                    "name": user.name,
                    "current_email": user.current_email,
                    "historical_emails": "; ".join(user.historical_emails),
                    "all_emails_count": len(user.all_emails),
                    "current_phone": user.current_phone,
                    "historical_phones": "; ".join(user.historical_phones),
                    "current_email_hash": user.current_email_hash,
                    "all_hashes_count": len(user.all_email_hashes),
                    "audit_changes_count": len(user.audit_history),
                })
            else:
                rows.append({
                    "case_id": cid,
                    "request_email": req_email,
                    "email_type": "UNRESOLVED",
                    "user_id": None,
                    "name": None,
                    "current_email": None,
                    "historical_emails": None,
                    "all_emails_count": 0,
                    "current_phone": None,
                    "historical_phones": None,
                    "current_email_hash": None,
                    "all_hashes_count": 0,
                    "audit_changes_count": 0,
                })

        return pd.DataFrame(rows)

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics on identity resolution coverage."""
        all_eval_cases = len(self.ingestor.deletion_requests)
        all_sample_cases = len(self.ingestor.sample_requests)

        eval_resolved_df = self.resolve_all_requests(self.ingestor.deletion_requests)
        sample_resolved_df = self.resolve_all_requests(self.ingestor.sample_requests)

        eval_resolved_count = (eval_resolved_df["email_type"] != "UNRESOLVED").sum()
        eval_hist_count = (eval_resolved_df["email_type"] == "HISTORICAL").sum()
        eval_curr_count = (eval_resolved_df["email_type"] == "CURRENT").sum()

        sample_resolved_count = (sample_resolved_df["email_type"] != "UNRESOLVED").sum()
        sample_hist_count = (sample_resolved_df["email_type"] == "HISTORICAL").sum()
        sample_curr_count = (sample_resolved_df["email_type"] == "CURRENT").sum()

        return {
            "total_users": len(self._users_by_id),
            "users_with_audit_history": sum(1 for u in self._users_by_id.values() if u.has_historical_changes),
            "users_with_email_changes": sum(1 for u in self._users_by_id.values() if u.has_email_changes),
            "sample_requests": {
                "total": all_sample_cases,
                "resolved": int(sample_resolved_count),
                "current_email_matches": int(sample_curr_count),
                "historical_email_matches": int(sample_hist_count),
                "resolution_rate": f"{sample_resolved_count / all_sample_cases * 100:.1f}%",
            },
            "eval_requests": {
                "total": all_eval_cases,
                "resolved": int(eval_resolved_count),
                "current_email_matches": int(eval_curr_count),
                "historical_email_matches": int(eval_hist_count),
                "resolution_rate": f"{eval_resolved_count / all_eval_cases * 100:.1f}%",
            },
        }


# ---------------------------------------------------------------------------
# Deliverable Function (One-Line Helper for Other Team Members)
# ---------------------------------------------------------------------------

_GLOBAL_RESOLVER: Optional[IdentityResolver] = None


def resolve_identity_for_request(
    request: Union[str, Dict[str, Any], pd.Series, DeletionRequest],
    dataset_dir: Optional[Union[str, Path]] = None,
) -> Optional[UserIdentity]:
    """
    DELIVERABLE FUNCTION:
    Given a deletion request (case_id, email, dictionary, pandas Series, or DeletionRequest),
    returns the correct user and their known identifiers.

    Example usage by other team members:
        >>> from identity import resolve_identity_for_request
        >>> user = resolve_identity_for_request("case_01")
        >>> print(user.user_id, user.name, user.all_emails)
        user_01 Amina El Masri {'amina.elmasri@gmail.com'}

        >>> user = resolve_identity_for_request("nadia.ionescu@yahoo.com")
        >>> print(user.user_id, user.current_email, user.historical_emails)
        user_10 n.petrescu@yahoo.com ['nadia.ionescu@yahoo.com', 'nadia.petrescu@yahoo.com']
    """
    global _GLOBAL_RESOLVER
    if _GLOBAL_RESOLVER is None:
        _GLOBAL_RESOLVER = IdentityResolver(dataset_dir)
    return _GLOBAL_RESOLVER.resolve_user(request)


# ---------------------------------------------------------------------------
# CLI / Self-Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("Ghost-Print Identity Resolution Engine")
    print("=" * 65)

    resolver = IdentityResolver()
    stats = resolver.get_stats()

    print(f"\nTotal users in registry: {stats['total_users']}")
    print(f"Users with historical changes: {stats['users_with_audit_history']}")
    print(f"Users with email changes: {stats['users_with_email_changes']}")

    print("\nSample Requests Resolution:")
    for k, v in stats["sample_requests"].items():
        print(f"  - {k}: {v}")

    print("\nEvaluation Requests Resolution (518 cases):")
    for k, v in stats["eval_requests"].items():
        print(f"  - {k}: {v}")

    print("\n" + "-" * 65)
    print("Demonstration: Resolving Sample Requests")
    print("-" * 65)

    test_cases = ["case_01", "case_02", "case_03", "case_10", "case_32"]
    for cid in test_cases:
        req, user = resolver.resolve_case(cid)
        if req and user:
            is_hist = user.is_historical_email(req.email)
            email_tag = "[HISTORICAL EMAIL]" if is_hist else "[CURRENT EMAIL]"
            print(f"\nCase: {req.case_id} ({email_tag})")
            print(f"  Request Email  : {req.email}")
            print(f"  Resolved User  : {user.user_id} ({user.name})")
            print(f"  Current Email  : {user.current_email}")
            if user.historical_emails:
                print(f"  Historical Em  : {user.historical_emails}")
            print(f"  All Emails ({len(user.all_emails)}): {user.all_emails}")
            print(f"  All Phones ({len(user.all_phones)}): {user.all_phones}")
            print(f"  Email SHA-256  : {user.current_email_hash}")
            print(f"  Search Terms   : {len(user.get_search_terms())} terms available for evidence scan")

    print("\n" + "=" * 65)
    print("Deliverable function check: resolve_identity_for_request")
    sample_user = resolve_identity_for_request("case_01")
    assert sample_user is not None, "Failed to resolve case_01"
    print(f"Verified resolve_identity_for_request('case_01') -> {sample_user}")
    print("Identity resolution module verified successfully!")

