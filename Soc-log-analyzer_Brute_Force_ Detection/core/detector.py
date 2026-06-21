from collections import defaultdict
from datetime import datetime, timedelta


class BruteForceDetector:
    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

        self.failed_attempts = defaultdict(list)
        self.alerts = []

    # -----------------------------
    # MAIN ENTRY POINT
    # -----------------------------
    def analyze(self, logs):
        for log in logs:

            # safety check (prevents crashes)
            if "event" not in log or "ip" not in log:
                continue

            if log["event"] == "LOGIN_FAILED":
                self.handle_failed(log)

            elif log["event"] == "LOGIN_SUCCESS":
                self.handle_success(log)

        return self.alerts

    # -----------------------------
    # SAFE TIME PARSER
    # -----------------------------
    def parse_time(self, time_str):
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S"
        ]

        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except:
                continue

        # fallback if everything fails
        return datetime.now()

    # -----------------------------
    # FAILED LOGIN HANDLER
    # -----------------------------
    def handle_failed(self, log):
        ip = log["ip"]
        time = self.parse_time(log["timestamp"])

        self.failed_attempts[ip].append(time)

        # keep only events inside time window
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip]
            if time - t <= self.window
        ]

        # brute force detection rule
        if len(self.failed_attempts[ip]) >= self.threshold:
            self.alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "message": f"Possible brute-force attack detected from {ip}",
                "attempts": len(self.failed_attempts[ip]),
                "time": str(time)
            })

    # -----------------------------
    # SUCCESS LOGIN HANDLER
    # -----------------------------
    def handle_success(self, log):
        ip = log["ip"]
        time = self.parse_time(log["timestamp"])

        # compromise detection (fail → success pattern)
        if len(self.failed_attempts[ip]) >= self.threshold:
            self.alerts.append({
                "type": "ACCOUNT_COMPROMISE",
                "ip": ip,
                "message": f"Possible account compromise detected from {ip}",
                "time": str(time)
            })

        # reset after success
        self.failed_attempts[ip] = []
