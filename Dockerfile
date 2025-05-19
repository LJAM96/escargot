# 1. Choose a base Python image
FROM python:3.8-slim

# 2. Set the working directory inside the container
WORKDIR /usr/src/app

# 3. Create directories for persistent data and Flask templates
RUN mkdir -p /usr/src/app/data /usr/src/app/certs /usr/src/app/templates

# 4. Copy all source code from the current directory (build context)
# This will now copy the MODIFIED settings.py
COPY . .

# 5. Copy your custom 'settings_local.py' <-- REMOVE THIS LINE
# COPY settings_local.py . # No longer needed

# --- Add copies for Admin GUI ---
COPY admin_gui.py .
COPY templates/ /usr/src/app/templates/
COPY supervisord.conf /etc/supervisor/conf.d/escargot-apps.conf
# --- End Admin GUI copies ---

# 6. Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    python3.8-dev \
    dos2unix \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# 7. Install Python packages (Flask will be picked up from requirements.txt)
RUN pip install --no-cache-dir -r requirements.txt python-dateutil # Ensure Flask is in requirements.txt

# 8. Ensure entrypoint script has correct line endings and is executable
RUN dos2unix ./entrypoint.sh && \
    chmod +x ./entrypoint.sh

# 9. Expose the necessary ports
# Escargot MSN
EXPOSE 1863
# Escargot MSN
EXPOSE 1864
# Escargot HTTP (if used by run_all.py)
EXPOSE 80
# Escargot HTTPS (if used by run_all.py)
EXPOSE 443
# Escargot IRC (if used by run_all.py)
EXPOSE 6667
# Admin GUI (Flask app port)
EXPOSE 5001

# 10. Set the entrypoint script as the command to run (entrypoint will start supervisor)
ENTRYPOINT ["./entrypoint.sh"]