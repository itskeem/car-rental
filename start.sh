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

# Start the application
exec gunicorn app:app

