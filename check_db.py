import sqlite3

db_path = r"C:\Users\pinag\Downloads\cyber-threat-response\app\data\threat_logs.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Show all tables
print("Tables in DB:")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(cursor.fetchall())

# Show all rows in Threat table
print("\nRows in Threat table:")
try:
    cursor.execute("SELECT * FROM threat;")
    rows = cursor.fetchall()
    for row in rows:
        print(row)
except Exception as e:
    print("Error querying Threat table:", e)

conn.close()
