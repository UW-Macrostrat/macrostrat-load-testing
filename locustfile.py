# locustfile.py
from locust import HttpUser, task, between, events
import re
import time
from datetime import datetime
from collections import defaultdict
import os
import threading

# -----------------------
# Configuration / Envvars
# -----------------------
# LOGFILE: path to log (default "access.log")
# TIME_COMPRESSION_FACTOR: float (default 1.0)
# MAX_LINES: optional integer (default: all)
# MAX_DELAY_PER_REQUEST: cap per-request sleep in seconds (default: 5)

LOGFILE = os.getenv("LOGFILE", "access.log")
TIME_COMPRESSION_FACTOR = float(os.getenv("TIME_COMPRESSION_FACTOR", "1.0"))
MAX_LINES = int(os.getenv("MAX_LINES", "0")) or None
MAX_DELAY_PER_REQUEST = float(os.getenv("MAX_DELAY_PER_REQUEST", "5"))

# -----------------------
# Log parsing
# -----------------------
log_pattern = re.compile(
    r'(?P<ip>\S+) (?:\S+ ){2}\[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referrer>.*?)" "(?P<user_agent>.*?)" "-"'
)

def parse_log_line(line):
    match = log_pattern.match(line)
    if not match:
        return None
    try:
        timestamp = datetime.strptime(match['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return None
    try:
        size = int(match['size'])
    except Exception:
        size = 0
    return {
        "ip": match["ip"],
        "timestamp": timestamp,
        "method": match["method"],
        "path": match["path"],
        "status": int(match["status"]),
        "size": size,
        "referrer": match["referrer"],
        "user_agent": match["user_agent"],
    }

def load_sessions_from_log(logfile, max_lines=None):
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        if max_lines:
            lines = []
            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                lines.append(line)
        else:
            lines = f.readlines()

    parsed = [parse_log_line(line) for line in lines]
    parsed = [p for p in parsed if p is not None]

    sessions = defaultdict(list)
    for req in parsed:
        sessions[req["ip"]].append(req)

    for reqs in sessions.values():
        reqs.sort(key=lambda r: r["timestamp"])

    return list(sessions.values())


class SessionRegistry:
    def __init__(self, sessions):
        self.sessions = sessions  
        self.lock = threading.Lock()
        self.index = 0

    def get_next_session(self):
        with self.lock:
            if not self.sessions:
                return []
            session = self.sessions[self.index % len(self.sessions)]
            self.index += 1
            return session

SESSION_REGISTRY = None


class LogReplayUser(HttpUser):
    wait_time = between(0, 0) 

    def on_start(self):
        global SESSION_REGISTRY
        if SESSION_REGISTRY is None:
            raise RuntimeError("SESSION_REGISTRY is not initialized. Ensure events.init loaded the log file.")
        self.user_requests = SESSION_REGISTRY.get_next_session()
        self._index = 0
        self._started = time.time()

    @task
    def replay_session(self):
        if not self.user_requests:
            try:
                self.stop(True)
            except Exception:
                raise

            return

        if self._index >= len(self.user_requests):
            try:
                self.stop(True)
            except Exception:
                raise
            return

        req = self.user_requests[self._index]
        self._index += 1

        if self._index > 1:
            prev = self.user_requests[self._index - 2]
            delay = (req["timestamp"] - prev["timestamp"]).total_seconds()
            delay *= TIME_COMPRESSION_FACTOR
            if delay > 0:
                time.sleep(min(delay, MAX_DELAY_PER_REQUEST))

        headers = {"User-Agent": req.get("user_agent", "locust-logreplay")}
        method = req["method"].upper()
        path = req["path"]

        try:
            start = time.time()
            response = self.client.request(method, path, headers=headers, timeout=10, catch_response=False)
            elapsed = (time.time() - start) * 1000.0  # Locust expects ms for events
            if response.status_code >= 400:
                events.request_failure.fire(
                    request_type=method,
                    name=path,
                    response_time=elapsed,
                    response_length=len(response.content) if response.content is not None else 0,
                    exception=Exception(f"HTTP {response.status_code}")
                )
            else:
                events.request_success.fire(
                    request_type=method,
                    name=path,
                    response_time=elapsed,
                    response_length=len(response.content) if response.content is not None else 0,
                )
        except Exception as e:
            events.request_failure.fire(
                request_type=method,
                name=path,
                response_time=0,
                response_length=0,
                exception=e
            )


@events.init.add_listener
def on_locust_init(environment, **_kwargs):
    global SESSION_REGISTRY
    logfile = os.getenv("LOGFILE", LOGFILE)
    compression = float(os.getenv("TIME_COMPRESSION_FACTOR", TIME_COMPRESSION_FACTOR))
    max_lines = int(os.getenv("MAX_LINES", "0")) or MAX_LINES

    if not os.path.exists(logfile):
        print(f"[locust-log-replay] WARNING: logfile '{logfile}' does not exist. No sessions loaded.")
        SESSION_REGISTRY = SessionRegistry([])
        return

    sessions = load_sessions_from_log(logfile, max_lines=max_lines)
    # sessions is a list of session lists
    SESSION_REGISTRY = SessionRegistry(sessions)
    globals()["TIME_COMPRESSION_FACTOR"] = compression

    print(f"[locust-log-replay] Loaded {len(sessions)} sessions from {logfile}")
    print(f"[locust-log-replay] Time compression factor: {compression}")
