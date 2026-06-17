"""
SITBank Admin App Entrypoint.
Runs the administrative boundary separately from the customer application.
"""
import os

# Enforce admin component boundary before initialization
os.environ["SITBANK_COMPONENT"] = "admin"

from app import create_app

app = create_app(config_name=os.getenv("APP_ENV", "development"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002)