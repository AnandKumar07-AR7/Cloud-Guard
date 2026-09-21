"""
Phase 2 Tests — Scan Store (In-Memory Repository)
"""
import threading
import pytest
from services.scan_models import ScanRecord, ScanStatus
from services.scan_store import ScanStore


def _make_record(**kwargs) -> ScanRecord:
    defaults = dict(provider="demo", account_id="123456789012", mode="demo")
    defaults.update(kwargs)
    return ScanRecord(**defaults)


class TestScanStoreBasic:
    def test_save_and_get(self):
        store = ScanStore()
        rec = _make_record()
        store.save(rec)
        retrieved = store.get(rec.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == rec.scan_id

    def test_get_missing_returns_none(self):
        store = ScanStore()
        assert store.get("no-such-id") is None

    def test_save_updates_existing(self):
        store = ScanStore()
        rec = _make_record()
        store.save(rec)
        rec.mark_status(ScanStatus.COMPLETED)
        store.save(rec)
        assert store.get(rec.scan_id).status == ScanStatus.COMPLETED

    def test_len_tracks_records(self):
        store = ScanStore()
        assert len(store) == 0
        store.save(_make_record())
        assert len(store) == 1
        store.save(_make_record())
        assert len(store) == 2

    def test_delete_removes_record(self):
        store = ScanStore()
        rec = _make_record()
        store.save(rec)
        assert store.delete(rec.scan_id) is True
        assert store.get(rec.scan_id) is None

    def test_delete_missing_returns_false(self):
        store = ScanStore()
        assert store.delete("nonexistent") is False


class TestScanStoreList:
    def test_list_most_recent_first(self):
        store = ScanStore()
        r1 = _make_record()
        r2 = _make_record()
        r3 = _make_record()
        store.save(r1)
        store.save(r2)
        store.save(r3)
        items = store.list()
        assert items[0].scan_id == r3.scan_id

    def test_list_pagination(self):
        store = ScanStore()
        for _ in range(10):
            store.save(_make_record())
        page1 = store.list(limit=3, offset=0)
        page2 = store.list(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        ids1 = {r.scan_id for r in page1}
        ids2 = {r.scan_id for r in page2}
        assert ids1.isdisjoint(ids2)

    def test_list_filter_by_status(self):
        store = ScanStore()
        r1 = _make_record()
        r2 = _make_record()
        r1.mark_status(ScanStatus.COMPLETED)
        r2.mark_status(ScanStatus.FAILED)
        store.save(r1)
        store.save(r2)
        completed = store.list(status=ScanStatus.COMPLETED)
        assert all(r.status == ScanStatus.COMPLETED for r in completed)


class TestScanStoreBoundedCapacity:
    def test_evicts_oldest_when_full(self):
        store = ScanStore(max_records=3)
        ids = []
        for _ in range(5):
            r = _make_record()
            store.save(r)
            ids.append(r.scan_id)
        # First 2 should be evicted
        assert store.get(ids[0]) is None
        assert store.get(ids[1]) is None
        # Last 3 should remain
        assert store.get(ids[2]) is not None
        assert store.get(ids[3]) is not None
        assert store.get(ids[4]) is not None


class TestScanStoreThreadSafety:
    def test_concurrent_saves_no_corruption(self):
        store = ScanStore(max_records=1000)
        errors = []

        def save_records():
            try:
                for _ in range(20):
                    store.save(_make_record())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=save_records) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(store) == 100
