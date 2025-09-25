from app import create_app, db
from app.models import Threat

app = create_app()

with app.app_context():
    print("Database URI:", app.config["SQLALCHEMY_DATABASE_URI"])

    # Clear existing data for testing
    Threat.query.delete()

    threat1 = Threat(name="SQL Injection", description="Database injection attack", severity="High")
    threat2 = Threat(name="XSS", description="Cross-site scripting attack", severity="Medium")

    db.session.add_all([threat1, threat2])
    db.session.commit()

    print("✅ Sample data inserted successfully!")
