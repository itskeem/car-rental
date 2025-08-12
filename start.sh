#!/bin/bash
set -e

# Create instance directory if it doesn't exist
mkdir -p instance

# Initialize database if it doesn't exist
if [ ! -f "instance/database.db" ]; then
    echo "Initializing new database..."
    flask shell <<EOF
from app import db
db.create_all()
exit()
EOF
fi

# Start Gunicorn (using Python module syntax for reliability)
exec python -m gunicorn --bind 0.0.0.0:10000 app:app
