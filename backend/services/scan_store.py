"""
CloudGuard — In-Memory Scan Store

Provides a thread-safe in-memory store for ScanRecord objects.
Phase 5 will replace this with a PostgreSQL-backed repository.

The ScanStore interface is designed so the service layer never
directly accesses storage primitives — it always goes through
the store's typed methods. This makes the PostgreSQL migration clean.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Dict, Iterator, List, Optional

from services.scan_models import ScanRecord, ScanStatus


class ScanStore:
    """
    Thread-safe in-memory store for ScanRecord objects.

    Implements a bounded LRU cache so the server does not grow
    unbounded in long-running processes.

    Phase 5 contract: Replace this class with a PostgreSQL-backed
    ScanRepository that exposes the same public interface.
    """

    def __init__(self, max_records: int = 500) -> None:
        self._store: OrderedDict[str, ScanRecord] = OrderedDict()
        self._lock = threading.Lock()
        self._max_records = max_records

    def save(self, record: ScanRecord) -> ScanRecord:
        """Persist (or update) a ScanRecord."""
        with self._lock:
            self._store[record.scan_id] = record
            # Evict oldest if over capacity
            while len(self._store) > self._max_records:
                self._store.popitem(last=False)
        return record

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        """Return a ScanRecord by ID, or None if not found."""
        with self._lock:
            return self._store.get(scan_id)

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[ScanStatus] = None,
        mode: Optional[str] = None,
    ) -> List[ScanRecord]:
        """
        Return a paginated, optionally-filtered list of scans.
        Most recent scans first.
        """
        with self._lock:
            records = list(reversed(list(self._store.values())))

        if status:
            records = [r for r in records if r.status == status]
        if mode:
            records = [r for r in records if r.mode == mode]

        return records[offset: offset + limit]

    def count(self, status: Optional[ScanStatus] = None) -> int:
        """Return total count of stored scans, optionally filtered by status."""
        with self._lock:
            if status is None:
                return len(self._store)
            return sum(1 for r in self._store.values() if r.status == status)

    def delete(self, scan_id: str) -> bool:
        """Remove a scan record. Returns True if removed, False if not found."""
        with self._lock:
            if scan_id in self._store:
                del self._store[scan_id]
                return True
            return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# Module-level singleton (replaced by DI in future phases)
_scan_store: Optional[ScanStore] = None


def get_scan_store() -> ScanStore:
    """Return the global ScanStore singleton."""
    global _scan_store
    if _scan_store is None:
        _scan_store = ScanStore()
    return _scan_store
