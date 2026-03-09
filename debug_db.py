import sqlite3
import os

DB_PATH = "vulnerabilities_enforced.db"

def debug():
    if not os.path.exists(DB_PATH):
        print(f"❌ {DB_PATH} not found.")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("--- Scan Sessions ---")
    cursor.execute("SELECT id, created_at FROM scan_sessions ORDER BY created_at DESC LIMIT 5")
    sessions = cursor.fetchall()
    for s in sessions:
        print(s)
        cursor.execute("SELECT count(*), status FROM vulnerabilities WHERE scan_session_id=? GROUP BY status", (s[0],))
        counts = cursor.fetchall()
        print(f"  Vulnerabilities: {counts}")
        
    conn.close()

if __name__ == "__main__":
    debug()
