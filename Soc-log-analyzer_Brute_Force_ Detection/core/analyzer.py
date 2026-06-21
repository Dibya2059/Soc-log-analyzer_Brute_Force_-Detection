import subprocess
import re
from datetime import datetime


class LogAnalyzer:
    def __init__(self, service="ssh"):
        self.service = service

    def fetch_logs(self):
        try:
            return subprocess.check_output(
                ["journalctl", "-u", self.service, "--no-pager"],
                text=True
            )
        except:
            return ""

    def parse_logs(self):
        logs = []
        raw_logs = self.fetch_logs()

        for line in raw_logs.splitlines():
            line_lower = line.lower()

            ip = self.extract_ip(line)
            timestamp = self.extract_time(line)

            event_type = None

            # -------------------------
            # LOGIN FAILURE DETECTION
            # -------------------------
            if (
                "failed password" in line_lower or
                "password check failed" in line_lower or
                "authentication failure" in line_lower or
                "chkpwd" in line_lower
            ):
                event_type = "LOGIN_FAILED"

            # -------------------------
            # LOGIN SUCCESS DETECTION
            # -------------------------
            elif (
                "accepted password" in line_lower or
                "session opened" in line_lower
            ):
                event_type = "LOGIN_SUCCESS"

            # -------------------------
            # STORE EVENT (FIXED)
            # -------------------------
            if event_type:
                logs.append({
                    "event": event_type,
                    "ip": ip if ip else "LOCAL",
                    "timestamp": timestamp
                })

        return logs

    def extract_ip(self, line):
        patterns = [
            r"from (\d+\.\d+\.\d+\.\d+)",
            r"\((\d+\.\d+\.\d+\.\d+)\)"
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

        return None

    def extract_time(self, line):
        try:
            pattern = r"([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)"
            match = re.search(pattern, line)

            if match:
                return str(datetime.strptime(
                    match.group(1),
                    "%b %d %H:%M:%S"
                ).replace(year=datetime.now().year))

        except:
            pass

        return str(datetime.now())
