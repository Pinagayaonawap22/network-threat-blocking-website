import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = "my_key"
    DEBUG = True
    db_path = os.path.join(basedir, "app", "data", "threat_logs.db")
    db_path = db_path.replace("\\", "/")  # normalize for Windows paths
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

