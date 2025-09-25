from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
migrate = Migrate()
DATA_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    db.init_app(app)
    migrate.init_app(app, db)

    data_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
    print("Data directory path:", data_dir)
    if not os.path.exists(data_dir):
        print("Data directory does not exist, creating it now.")
        os.makedirs(data_dir)
    else:
        print("Data directory exists.")

    db_path = os.path.join(data_dir, 'threat_logs.db')
    print("Database full path:", db_path)
    print("Does DB file exist?", os.path.exists(db_path))

    from .routes import main
    app.register_blueprint(main)

    return app
