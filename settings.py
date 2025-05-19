import os
import json # Needed for list parsing example

# Helper function to convert env var strings to boolean
def get_bool_env(var_name, default=False):
    value = os.environ.get(var_name, str(default))
    return value.lower() in ('true', '1', 't', 'y', 'yes')

# --- Database Settings ---
# Use /usr/src/app/data as the default path within the container
DEFAULT_DB_PATH = 'sqlite:///data/escargot.sqlite'
DEFAULT_STATS_DB_PATH = 'sqlite:///data/stats.sqlite'
DB = os.environ.get('ESCARGOT_DB', DEFAULT_DB_PATH)
STATS_DB = os.environ.get('ESCARGOT_STATS_DB', DEFAULT_STATS_DB_PATH)

# --- Certificate Settings ---
DEFAULT_CERT_DIR = 'certs' # Relative to WORKDIR /usr/src/app
CERT_DIR = os.environ.get('ESCARGOT_CERT_DIR', DEFAULT_CERT_DIR)
# CERT_ROOT probably doesn't need env var unless explicitly needed
CERT_ROOT = os.environ.get('ESCARGOT_CERT_ROOT', 'CERT_ROOT') 

# --- Hostname Settings ---
# Defaulting to localhost might be safer for initial setup if not overridden
DEFAULT_HOST = 'localhost' 
TARGET_HOST = os.environ.get('ESCARGOT_TARGET_HOST', DEFAULT_HOST)
LOGIN_HOST = os.environ.get('ESCARGOT_LOGIN_HOST', TARGET_HOST) # Default LOGIN_HOST to TARGET_HOST
STORAGE_HOST = os.environ.get('ESCARGOT_STORAGE_HOST', LOGIN_HOST) # Default STORAGE_HOST to LOGIN_HOST

# --- Passwords ---
# IMPORTANT: These should ALWAYS be set via environment variables in production!
# Defaults below are highly insecure.
SYSBOARD_PASS = os.environ.get('ESCARGOT_SYSBOARD_PASS', 'insecure_default_root')
SITE_LINK_PASSWORD = os.environ.get('ESCARGOT_SITE_LINK_PASSWORD', 'insecure_default_password')

# --- Debug Flags ---
DEBUG = get_bool_env('ESCARGOT_DEBUG', False)
DEBUG_MSNP = get_bool_env('ESCARGOT_DEBUG_MSNP', False)
DEBUG_YMSG = get_bool_env('ESCARGOT_DEBUG_YMSG', False)
DEBUG_IRC = get_bool_env('ESCARGOT_DEBUG_IRC', False)
DEBUG_S2S = get_bool_env('ESCARGOT_DEBUG_S2S', False)
DEBUG_HTTP_REQUEST = get_bool_env('ESCARGOT_DEBUG_HTTP_REQUEST', False)
DEBUG_HTTP_REQUEST_FULL = get_bool_env('ESCARGOT_DEBUG_HTTP_REQUEST_FULL', False)
# Keep DEBUG_SYSBOARD default as True based on original file? Or make it configurable?
DEBUG_SYSBOARD = get_bool_env('ESCARGOT_DEBUG_SYSBOARD', True) 

# --- Feature Flags ---
ENABLE_S2S = get_bool_env('ESCARGOT_ENABLE_S2S', False)
ENABLE_FRONT_MSN = get_bool_env('ESCARGOT_ENABLE_FRONT_MSN', True) # Default True
ENABLE_FRONT_YMSG = get_bool_env('ESCARGOT_ENABLE_FRONT_YMSG', False)
ENABLE_FRONT_IRC = get_bool_env('ESCARGOT_ENABLE_FRONT_IRC', False)
ENABLE_FRONT_IRC_SSL = get_bool_env('ESCARGOT_ENABLE_FRONT_IRC_SSL', False)
ENABLE_FRONT_API = get_bool_env('ESCARGOT_ENABLE_FRONT_API', False)
ENABLE_FRONT_BOT = get_bool_env('ESCARGOT_ENABLE_FRONT_BOT', False)
ENABLE_FRONT_DEVBOTS = get_bool_env('ESCARGOT_ENABLE_FRONT_DEVBOTS', False)

# --- Service Keys (Example using comma-separated string) ---
_service_keys_str = os.environ.get('ESCARGOT_SERVICE_KEYS', '')
SERVICE_KEYS = [key.strip() for key in _service_keys_str.split(',') if key.strip()]
# Example using JSON string (alternative):
# SERVICE_KEYS = json.loads(os.environ.get('ESCARGOT_SERVICE_KEYS_JSON', '[]'))

# --- REMOVE settings_local.py import ---
# We no longer need this section:
# try:
#	from settings_local import *
# except ImportError as ex:
#	raise Exception("Please create settings_local.py") from ex

print("SETTINGS: Loaded settings, TARGET_HOST set to:", TARGET_HOST) # Add a print for verification