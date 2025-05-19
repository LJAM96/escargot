#!/bin/sh
set -e

mkdir -p /usr/src/app/data /usr/src/app/certs
chown -R root:root /usr/src/app/data /usr/src/app/certs
chmod -R 700 /usr/src/app/data /usr/src/app/certs

echo "ENTRYPOINT: Setting PYTHONPATH to /usr/src/app"
export PYTHONPATH=/usr/src/app

echo "ENTRYPOINT: Creating/Updating database schema using script/dbcreate.py..."
python script/dbcreate.py
echo "ENTRYPOINT: Database schema script finished."

echo "ENTRYPOINT: Starting Supervisor to manage Escargot server and Admin GUI..."
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
# Note: The supervisord.conf specified here is the main one.
# Supervisor will include files from /etc/supervisor/conf.d/ like escargot-apps.conf