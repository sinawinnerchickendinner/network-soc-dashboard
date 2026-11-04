"""
parse_alerts.py - reads Suricata alert log lines and stores them in SQLite.
Usage:  python parse_alerts.py [logfile]      (default: suricata_alerts.log)
Safe to re-run: alerts already in the database are skipped, not duplicated.
"""
import re
import sqlite3
import sys

DB_FILE = "alerts.db"
LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "suricata_alerts.log"

PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+\[\*\*\]\s+\[\d+:(?P<sid>\d+):\d+\]\s+"
    r"(?P<message>.*?)\s+\[\*\*\]\s+\[Classification:.*?\]\s+"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
)


def setup(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, sid TEXT, message TEXT, priority INTEGER,
        protocol TEXT, src_ip TEXT, src_port INTEGER,
        dst_ip TEXT, dst_port INTEGER)""")
    # stops the same alert being stored twice if the script is run again
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS uniq_alert ON alerts
        (timestamp, sid, src_ip, src_port, dst_ip, dst_port)""")


def main():
    conn = sqlite3.connect(DB_FILE)
    setup(conn)
    added = skipped = bad = 0
    with open(LOG_FILE, "r") as f:
        for line in f:
            m = PATTERN.match(line.strip())
            if not m:
                bad += 1
                continue
            d = m.groupdict()
            cur = conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (timestamp, sid, message, priority, protocol, src_ip, src_port, dst_ip, dst_port)
                   VALUES (:timestamp, :sid, :message, :priority, :protocol,
                           :src_ip, :src_port, :dst_ip, :dst_port)""", d)
            if cur.rowcount:
                added += 1
            else:
                skipped += 1
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    print(f"Added {added} new alerts, skipped {skipped} duplicates, "
          f"{bad} lines didn't match the format.")
    print(f"Database now holds {total} alerts.")


if __name__ == "__main__":
    main()
