import sqlite3

conn = sqlite3.connect('Output/security_intel.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [row[0] for row in cursor.fetchall()]

print(f"Total tables: {len(tables)}")
print(f"Tables: {', '.join(tables)}")
print(f"\nvt_runs exists: {'vt_runs' in tables}")

if 'vt_runs' not in tables:
    print("\nWARNING: vt_runs table is missing!")
    print("Creating vt_runs table now...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vt_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP,
            scan_type TEXT,
            files_processed INTEGER DEFAULT 0,
            new_scans INTEGER DEFAULT 0,
            malicious_count INTEGER DEFAULT 0,
            clean_count INTEGER DEFAULT 0,
            excluded_vendors_added TEXT,
            excluded_vendors_removed TEXT
        )
    ''')
    conn.commit()
    print("OK: vt_runs table created successfully!")

conn.close()
