from core.analyzer import LogAnalyzer
from core.detector import BruteForceDetector


def main():
    print("\n=== SOC LOG ANALYZER STARTED ===\n")
    logs = [
        {"event": "LOGIN_FAILED", "ip": "192.168.1.10", "timestamp": "t1"},
        {"event": "LOGIN_FAILED", "ip": "192.168.1.10", "timestamp": "t2"},
        {"event": "LOGIN_FAILED", "ip": "192.168.1.10", "timestamp": "t3"},
        {"event": "LOGIN_FAILED", "ip": "192.168.1.10", "timestamp": "t4"},
        {"event": "LOGIN_FAILED", "ip": "192.168.1.10", "timestamp": "t5"},
    ]
   # analyzer = LogAnalyzer(service="ssh")
    #logs = analyzer.parse_logs()

    detector = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = detector.analyze(logs)

    print("\n=== SECURITY ALERTS ===\n")

    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
        print(f"[{alert['type']}]")
        print(f"IP: {alert['ip']}")
        print(f"Message: {alert['message']}")
        print(f"Time: {alert['time']}")
        print("-" * 40)
    print(logs)

if __name__ == "__main__":
    main()
