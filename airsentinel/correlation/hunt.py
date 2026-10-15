"""Signal Hunting / Geiger Counter Direction-Finding Engine.

Ported from Fieldwatch's Hunt.kt.
Computes relative-loudness proximity cues (VERY_CLOSE, CLOSER, FURTHER, SAME,
WAITING, QUIET, GONE) and Geiger-counter acoustic tick intervals (90ms..1400ms).
"""
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple
from airsentinel.models import HuntCue


class SignalHunter:
    RECENT_SEC = 4.0
    EARLIER_FROM_SEC = 16.0
    EARLIER_TO_SEC = 4.0
    STEP_DB = 3.0
    QUIET_SEC = 10.0
    GONE_SEC = 35.0
    VERY_CLOSE_DBM = -45.0
    TICK_LOUD_DBM = -40
    TICK_QUIET_DBM = -90
    TICK_FAST_MS = 90
    TICK_SLOW_MS = 1400

    def __init__(self):
        # mac_or_uuid -> deque of (timestamp_sec, rssi)
        self._samples: Dict[str, Deque[Tuple[float, int]]] = defaultdict(lambda: deque(maxlen=120))
        self._last_seen: Dict[str, float] = {}

    def reset(self):
        self._samples.clear()
        self._last_seen.clear()

    def record_sample(self, mac_or_uuid: str, rssi: int, now: Optional[float] = None):
        ts = now if now is not None else time.time()
        self._samples[mac_or_uuid].append((ts, rssi))
        self._last_seen[mac_or_uuid] = ts

    @classmethod
    def tick_interval_ms(cls, rssi: Optional[int], cue: HuntCue) -> Optional[int]:
        if rssi is None or cue in (HuntCue.QUIET, HuntCue.GONE):
            return None
        clamped = max(cls.TICK_QUIET_DBM, min(cls.TICK_LOUD_DBM, rssi))
        # Normalized 0.0 (loudest -40 dBm) to 1.0 (quietest -90 dBm)
        ratio = (cls.TICK_LOUD_DBM - clamped) / float(cls.TICK_LOUD_DBM - cls.TICK_QUIET_DBM)
        return int(cls.TICK_FAST_MS + ratio * (cls.TICK_SLOW_MS - cls.TICK_FAST_MS))

    @classmethod
    def proximity_percent(cls, rssi: Optional[int]) -> int:
        if rssi is None:
            return 0
        clamped = max(-95, min(-35, rssi))
        return int(((clamped - (-95)) / 60.0) * 100)

    def evaluate(self, mac_or_uuid: str, now: Optional[float] = None) -> Dict[str, Any]:
        ts = now if now is not None else time.time()
        last_ts = self._last_seen.get(mac_or_uuid)
        samples = list(self._samples.get(mac_or_uuid, []))

        if last_ts is None or not samples:
            return {
                "mac_or_uuid": mac_or_uuid,
                "cue": HuntCue.GONE.value,
                "last_rssi": None,
                "recent_avg_dbm": None,
                "earlier_avg_dbm": None,
                "delta_db": None,
                "tick_ms": None,
                "proximity_pct": 0,
                "age_sec": None,
                "samples": [],
            }

        age_sec = round(ts - last_ts, 1)
        last_rssi = samples[-1][1]

        if age_sec > self.GONE_SEC:
            cue = HuntCue.GONE
            recent_avg = None
            earlier_avg = None
            delta = None
        elif age_sec > self.QUIET_SEC:
            cue = HuntCue.QUIET
            recent_avg = None
            earlier_avg = None
            delta = None
        else:
            recent = [s[1] for s in samples if (ts - s[0]) <= self.RECENT_SEC]
            earlier = [
                s[1]
                for s in samples
                if self.EARLIER_TO_SEC < (ts - s[0]) <= self.EARLIER_FROM_SEC
            ]

            recent_avg = round(sum(recent) / len(recent), 1) if recent else float(last_rssi)
            earlier_avg = round(sum(earlier) / len(earlier), 1) if earlier else None

            if recent_avg >= self.VERY_CLOSE_DBM:
                cue = HuntCue.VERY_CLOSE
                delta = round(recent_avg - earlier_avg, 1) if earlier_avg is not None else 0.0
            elif earlier_avg is None:
                cue = HuntCue.WAITING
                delta = None
            else:
                delta = round(recent_avg - earlier_avg, 1)
                if delta >= self.STEP_DB:
                    cue = HuntCue.CLOSER
                elif delta <= -self.STEP_DB:
                    cue = HuntCue.FURTHER
                else:
                    cue = HuntCue.SAME

        tick_ms = self.tick_interval_ms(last_rssi, cue)
        prox_pct = self.proximity_percent(last_rssi) if cue not in (HuntCue.GONE, HuntCue.QUIET) else 0

        return {
            "mac_or_uuid": mac_or_uuid,
            "cue": cue.value,
            "last_rssi": last_rssi,
            "recent_avg_dbm": recent_avg,
            "earlier_avg_dbm": earlier_avg,
            "delta_db": delta,
            "tick_ms": tick_ms,
            "proximity_pct": prox_pct,
            "age_sec": age_sec,
            "samples": [{"ts": round(s[0], 1), "rssi": s[1]} for s in samples[-30:]],
        }


signal_hunter = SignalHunter()
