import os

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "app", "data", "threat_logs.db")

print("DB path:", db_path)

# Make sure the 'app/data' directory exists first
if not os.path.exists(os.path.join(basedir, "app", "data")):
    os.makedirs(os.path.join(basedir, "app", "data"))

# Create the file if it doesn't exist
open(db_path, 'a').close()
print("DB file created or already exists")
