import sqlite3

conn = sqlite3.connect('Output/security_intel.db')
cursor = conn.cursor()

print("Adding new columns to vt_runs table...")

try:
    cursor.execute('ALTER TABLE vt_runs ADD COLUMN successfully_scanned INTEGER DEFAULT 0')
    print("✓ Added successfully_scanned column")
except Exception as e:
    print(f"  successfully_scanned: {e}")

try:
    cursor.execute('ALTER TABLE vt_runs ADD COLUMN cached_count INTEGER DEFAULT 0')
    print("✓ Added cached_count column")
except Exception as e:
    print(f"  cached_count: {e}")

try:
    cursor.execute('ALTER TABLE vt_runs ADD COLUMN errors_count INTEGER DEFAULT 0')
    print("✓ Added errors_count column")
except Exception as e:
    print(f"  errors_count: {e}")

conn.commit()
conn.close()

print("\n✓ vt_runs table updated successfully!")
