"""
app.py - Flask dashboard that shows the Suricata alerts stored in alerts.db.
Run:  python app.py      then open  http://127.0.0.1:5000
"""
import sqlite3
from flask import Flask, render_template, request

app = Flask(__name__)
DB_FILE = "alerts.db"


def query(sql, params=()):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


@app.route("/")
def index():
    src = request.args.get("src_ip", "").strip()
    dst = request.args.get("dst_ip", "").strip()
    text = request.args.get("q", "").strip()

    # Filters are added with ? placeholders (never pasted into the SQL text),
    # so typing odd characters into the boxes can't break or attack the database.
    where, params = [], []
    if src:
        where.append("src_ip = ?")
        params.append(src)
    if dst:
        where.append("dst_ip = ?")
        params.append(dst)
    if text:
        where.append("message LIKE ?")
        params.append(f"%{text}%")
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    alerts = query(f"SELECT * FROM alerts {clause} ORDER BY timestamp DESC LIMIT 500", params)
    total = query(f"SELECT COUNT(*) AS n FROM alerts {clause}", params)[0]["n"]
    by_source = query(
        f"SELECT src_ip, COUNT(*) AS n FROM alerts {clause} "
        "GROUP BY src_ip ORDER BY n DESC LIMIT 5", params)
    sources = [r["src_ip"] for r in query("SELECT DISTINCT src_ip FROM alerts ORDER BY src_ip")]
    destinations = [r["dst_ip"] for r in query("SELECT DISTINCT dst_ip FROM alerts ORDER BY dst_ip")]

    return render_template("index.html", alerts=alerts, total=total, by_source=by_source,
                           sources=sources, destinations=destinations,
                           src=src, dst=dst, text=text)


if __name__ == "__main__":
    app.run(debug=True)
