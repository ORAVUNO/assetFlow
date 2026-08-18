"""Background scheduler: run persisted schedules on their interval.

A single daemon thread wakes every ``tick`` seconds and runs any schedule whose
interval has elapsed. Schedules live in the database (see ``db.Schedule``), so
they survive restarts; the thread simply picks up whatever is enabled.

A schedule only runs when its adapter is currently connected — connections are
in-memory, so after a restart the relevant adapter must reconnect (via the UI or
environment auto-connect) before its schedules resume.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

from . import db
from . import service


def tick_once(manager, now: Optional[datetime] = None) -> list:
    """Run every due schedule once. Returns a list of per-schedule outcomes.

    Pure enough to unit-test: pass a manager and a fixed ``now``.
    """
    now = now or datetime.now(timezone.utc)
    outcomes = []
    for sched in db.due_schedules(now):
        try:
            adapter = manager.get(sched["adapter"])
        except KeyError:
            db.mark_schedule_ran(sched["id"], now)
            outcomes.append({"id": sched["id"], "status": "unknown-adapter"})
            continue
        if not adapter.connected:
            # Leave last_run_at untouched so it fires as soon as it reconnects.
            outcomes.append({"id": sched["id"], "status": "skipped-disconnected"})
            continue
        try:
            if sched["query_id"] == "*":
                summary = service.run_all(adapter, limit=sched["limit"], time_range=sched["time_range"])
                outcomes.append({"id": sched["id"], "status": "ran-all", "summary": summary})
            else:
                query = adapter.registry.get_query(sched["query_id"])
                rec = service.run_and_save(adapter, query, limit=sched["limit"], time_range=sched["time_range"])
                outcomes.append({"id": sched["id"], "status": "ran", "row_count": rec.get("row_count")})
        except Exception as exc:
            outcomes.append({"id": sched["id"], "status": "error", "error": str(exc)})
        finally:
            db.mark_schedule_ran(sched["id"], now)
    return outcomes


class Scheduler:
    """Owns the daemon thread that calls :func:`tick_once` on an interval."""

    def __init__(self, manager, tick: float = 10.0):
        self.manager = manager
        self.tick = tick
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.started_at: Optional[datetime] = None
        self.last_tick_at: Optional[datetime] = None
        self.last_ran_count: int = 0

    def start(self) -> "Scheduler":
        if self._thread is not None:
            return self
        self.started_at = datetime.now(timezone.utc)
        self._thread = threading.Thread(target=self._loop, name="assetflow-scheduler", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict:
        running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "tick_seconds": self.tick,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "last_tick_at": self.last_tick_at.isoformat() if self.last_tick_at else None,
            "last_ran_count": self.last_ran_count,
        }

    def _loop(self) -> None:
        while not self._stop.wait(self.tick):
            self.last_tick_at = datetime.now(timezone.utc)
            try:
                outcomes = tick_once(self.manager)
                self.last_ran_count = sum(
                    1 for o in outcomes if o.get("status") in ("ran", "ran-all")
                )
            except Exception:
                # A scheduler tick must never take the thread down.
                pass
