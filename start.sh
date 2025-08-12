#!/bin/bash
set -e

# Create database directory if it doesn't exist
mkdir -p /tmp

# Initialize database if it doesn't exist
if [ ! -f "/tmp/database.db" ]; then
    echo "Initializing new database..."
    flask shell <<EOF
from app import db
db.create_all()
exit()
EOF
fi

# Start the application
exec gunicorn app:app
