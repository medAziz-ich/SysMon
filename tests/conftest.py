"""
tests/conftest.py
=================
Shared pytest configuration.

_SyncThread only intercepts known alert/notification thread targets so that
FastAPI-Users' internal threads (SQLAlchemy pool, event dispatch) keep running
normally and don't deadlock inside the TestClient event loop.
"""

import threading
import pytest
import server as _server


_SYNC_TARGETS = {"check_alerts", "_send_email", "_send_webhook"}


class _SyncThread(threading.Thread):
    """
    Runs alert/notification targets synchronously so tests can assert on
    alert state immediately without sleep().  All other threads (SQLAlchemy,
    FastAPI-Users internals) run in a real background thread as normal.
    """

    def start(self):
        name = getattr(self._target, "__name__", "") if self._target else ""
        if name in _SYNC_TARGETS:
            try:
                self._target(*self._args, **self._kwargs)
            except Exception:
                pass  # suppress to avoid PytestUnhandledThreadExceptionWarning
        else:
            super().start()   # normal background thread for everything else


@pytest.fixture(autouse=True)
def sync_alert_threads(monkeypatch):
    """Patch threading.Thread for the duration of each test."""
    monkeypatch.setattr(threading, "Thread", _SyncThread)
    yield
    monkeypatch.undo()
