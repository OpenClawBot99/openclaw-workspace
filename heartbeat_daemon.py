import sqlite3
import time
import logging
import threading
import json
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Callable, Dict
try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:
    BackgroundScheduler = None  # type: ignore

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("HeartbeatDaemon")


class SurvivalTier(str, Enum):
    NORMAL = "normal"
    LOW_COMPUTE = "low_compute"
    CRITICAL = "critical"
    DEAD = "dead"


@dataclass
class HeartbeatConfig:
    check_interval: int = 60
    balance_thresholds: Optional[Dict[str, float]] = None

    def __post_init__(self):
        if self.balance_thresholds is None:
            self.balance_thresholds = {
                "normal": 100,
                "low_compute": 20,
                "critical": 1,
                "dead": 0
            }


class Database:
    def __init__(self, db_path: str = "heartbeat.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS heartbeats (
                    id TEXT PRIMARY KEY,
                    enabled INTEGER,
                    schedule TEXT,
                    last_run TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS balance_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    balance REAL,
                    tier TEXT,
                    timestamp TEXT
                )
            """)
            conn.commit()

    def get_state(self, key: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT value FROM agent_state WHERE key = ?", (key,)
            )
            row = cursor.fetchone()
            return row[0] if row else None

    def set_state(self, key: str, value: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO agent_state (key, value) VALUES (?, ?)",
                (key, value)
            )
            conn.commit()

    def record_balance(self, balance: float, tier: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO balance_history (balance, tier, timestamp) VALUES (?, ?, ?)",
                (balance, tier, datetime.now().isoformat())
            )
            conn.commit()

    def get_heartbeat(self, id: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT id, enabled, schedule, last_run FROM heartbeats WHERE id = ?",
                (id,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "enabled": bool(row[1]),
                    "schedule": row[2],
                    "last_run": row[3]
                }
            return None

    def save_heartbeat(self, id: str, enabled: bool,                 schedule: str, last_run: Optional[str] = None):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO heartbeats (id, enabled, schedule, last_run) VALUES (?, ?, ?, ?)",
                (id, int(enabled), schedule, last_run)
            )
            conn.commit()


class CreditSystem:
    def get_balance(self) -> float:
        raise NotImplementedError


class MockCreditSystem(CreditSystem):
    def __init__(self, initial_balance: float = 150.0):
        self._balance = initial_balance

    def get_balance(self) -> float:
        return self._balance

    def set_balance(self, balance: float):
        self._balance = balance


class HeartbeatDaemon:
    def __init__(
        self,
        db: Database,
        credit_system: CreditSystem,
        config: Optional[HeartbeatConfig] = None,
        on_wake_request: Optional[Callable[[str], None]] = None,
        on_tier_change: Optional[Callable[[SurvivalTier], None]] = None
    ):
        self.db = db
        self.credit_system = credit_system
        self.config = config or HeartbeatConfig()
        self.on_wake_request = on_wake_request
        self.on_tier_change = on_tier_change
        self.scheduler = BackgroundScheduler() if BackgroundScheduler else None
        self._running = False
        self._current_tier = SurvivalTier.NORMAL

    def _get_tier(self, balance: float) -> SurvivalTier:
        thresholds = self.config.balance_thresholds or {}
        if balance <= thresholds.get("dead", 0):
            return SurvivalTier.DEAD
        elif balance <= thresholds.get("critical", 1):
            return SurvivalTier.CRITICAL
        elif balance <= thresholds.get("low_compute", 20):
            return SurvivalTier.LOW_COMPUTE
        return SurvivalTier.NORMAL

    def check_balance_and_update_tier(self):
        try:
            balance = self.credit_system.get_balance()
            new_tier = self._get_tier(balance)

            logger.info(f"Balance: {balance}, Tier: {new_tier}")
            self.db.record_balance(balance, new_tier.value)

            if new_tier != self._current_tier:
                logger.warning(f"Tier changed: {self._current_tier} -> {new_tier}")
                self._current_tier = new_tier
                self.db.set_state("survival_tier", new_tier.value)
                if self.on_tier_change:
                    self.on_tier_change(new_tier)

            if new_tier != SurvivalTier.DEAD:
                if self.on_wake_request:
                    self.on_wake_request(f"balance_check: {balance}")
            else:
                logger.error("CRITICAL: Balance depleted, entering DEAD state")

            self.db.save_heartbeat(
                "main",
                True,
                f"interval:{self.config.check_interval}",
                datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Error in check_balance_and_update_tier: {e}")

    def add_scheduled_task(self, task_id: str, interval_seconds: int, func: Callable):
        if self.scheduler:
            self.scheduler.add_job(
                func,
                'interval',
                seconds=interval_seconds,
                id=task_id,
                replace_existing=True
            )
            logger.info(f"Added scheduled task: {task_id} (every {interval_seconds}s)")

    def start(self):
        if self._running:
            logger.warning("Daemon already running")
            return

        saved_tier = self.db.get_state("survival_tier")
        if saved_tier:
            self._current_tier = SurvivalTier(saved_tier)
            logger.info(f"Restored tier: {self._current_tier}")

        self.add_scheduled_task(
            "balance_check",
            self.config.check_interval,
            self.check_balance_and_update_tier
        )

        if self.scheduler:
            self.scheduler.start()
        self._running = True
        logger.info(f"Heartbeat daemon started (check interval: {self.config.check_interval}s)")

    def stop(self):
        if not self._running:
            return
        if self.scheduler:
            self.scheduler.shutdown(wait=False)
        self._running = False
        logger.info("Heartbeat daemon stopped")

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "current_tier": self._current_tier.value,
            "config": {
                "check_interval": self.config.check_interval,
                "balance_thresholds": self.config.balance_thresholds
            }
        }


if __name__ == "__main__":
    credit_system = MockCreditSystem(initial_balance=150.0)
    db = Database("heartbeat.db")

    def on_tier_change(new_tier: SurvivalTier):
        print(f"⚠️  Tier changed to: {new_tier.value}")

    def on_wake_request(reason: str):
        print(f"🔔 Wake request: {reason}")

    config = HeartbeatConfig(
        check_interval=10,
        balance_thresholds={
            "normal": 100,
            "low_compute": 20,
            "critical": 1,
            "dead": 0
        }
    )

    daemon = HeartbeatDaemon(
        db=db,
        credit_system=credit_system,
        config=config,
        on_wake_request=on_wake_request,
        on_tier_change=on_tier_change
    )

    daemon.start()

    try:
        while True:
            time.sleep(5)
            credit_system.set_balance(credit_system.get_balance() - 5)
    except KeyboardInterrupt:
        daemon.stop()
