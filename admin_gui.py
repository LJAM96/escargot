# File: admin_gui.py (Updated)

from flask import Flask, render_template, request, redirect, url_for, flash, Response, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired
import os
import sys
import re
import socket # <--- IMPORT SOCKET MODULE

# Ensure the project root is in PYTHONPATH
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import Escargot components (Ensure this works correctly)
try:
    import settings
    from core.conn import Conn
    from core.db import User, UserContact, GroupChat, GroupChatMembership
    from util import misc
    try:
        from script.user import set_passwords
        print("ADMIN_GUI: Successfully imported set_passwords from script.user")
    except ImportError:
        print("ADMIN_GUI WARNING: Could not import set_passwords from script.user. Replicating hashing logic.", file=sys.stderr)
        from util import hash
        # Fallback password setting function if direct import fails
        def set_passwords(user_obj, new_password, support_old_msn=False, support_yahoo=False):
            if not hasattr(hash, 'hasher') or not hasattr(hash, 'hasher_md5'):
                 raise RuntimeError("ADMIN_GUI: Escargot's hash module or specific hashers not found/imported.")
            user_obj.password = hash.hasher.encode(new_password)
            if support_old_msn:
                 pw_md5 = hash.hasher_md5.encode(new_password)
                 user_obj.set_front_data('msn', 'pw_md5', pw_md5)
            else: user_obj.set_front_data('msn', 'pw_md5', None)
            if support_yahoo:
                 if hasattr(hash, 'hasher_md5') and hasattr(hash, 'hasher_md5crypt'):
                     pw_md5_unsalted = hash.hasher_md5.encode(new_password, salt = '')
                     user_obj.set_front_data('ymsg', 'pw_md5_unsalted', pw_md5_unsalted)
                     pw_md5crypt = hash.hasher_md5crypt.encode(new_password, salt = '$1$_2S43d5f')
                     user_obj.set_front_data('ymsg', 'pw_md5crypt', pw_md5crypt)
                 else: print("ADMIN_GUI: Yahoo hashers missing.", file=sys.stderr)
            else:
                 user_obj.set_front_data('ymsg', 'pw_md5_unsalted', None)
                 user_obj.set_front_data('ymsg', 'pw_md5crypt', None)

except ImportError as e:
    print(f"ADMIN_GUI FATAL: Could not import Escargot modules: {e}", file=sys.stderr)
    print(f"ADMIN_GUI sys.path: {sys.path}", file=sys.stderr)
    sys.exit("ADMIN_GUI Error: Core Escargot modules failed to import.")



app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_default_insecure_secret_key_change_me!')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

# Simple User class for Flask-Login
class AdminUser(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id == 'admin':
        return AdminUser('admin')
    return None

# Simple login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

# Hardcoded admin credentials (replace with secure method in production)
ADMIN_USERNAME = os.environ.get('ESCARGOT_ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.environ.get('ESCARGOT_ADMIN_PASS', 'adminpass')

# --- Registry Configuration Data ---
CLIENT_REG_CONFIGS = {
    "MSN Messenger 7.5": {
        "path": r"Software\Microsoft\MessengerService",
        "keys": { "Server": ("REG_SZ", "{server_ip}"), "PassportServer": ("REG_SZ", "{server_ip}"), }
    },
    "Windows Live Messenger 8.5": {
        "path": r"Software\Microsoft\Windows Live\Messenger",
        "keys": {
            "Server": ("REG_SZ", "{server_ip}"), "PassportUrl": ("REG_SZ", "{server_ip}"),
            "LoginCert": ("DELETE", None), "ConfigServer": ("REG_SZ", "{server_ip}"),
            "ContactsServer": ("REG_SZ", "{server_ip}"), "StorageServer": ("REG_SZ", "{server_ip}"),
            "PassportEnvironment": ("DELETE", None), "SecureConfig": ("REG_DWORD", 0),
            "SecureLogin": ("REG_DWORD", 0),
        }
    },
    "Windows Live Messenger 2009": {
        "path": r"Software\Microsoft\Windows Live\Messenger",
        "keys": {
            "Server": ("REG_SZ", "{server_ip}"), "PassportServer": ("REG_SZ", "{server_ip}"),
            "PassportRSTServer": ("REG_SZ", "{server_ip}"), "LoginCert": ("DELETE", None),
            "ConfigHost": ("REG_SZ", "{server_ip}"), "ContactsHost": ("REG_SZ", "{server_ip}"),
            "StorageHost": ("REG_SZ", "{server_ip}"), "PassportUpdateServer": ("DELETE", None),
            "SecureConfig": ("REG_DWORD", 0),
        }
    },
}

# --- Helper Function to Check Service Status via Socket ---
def check_service_status(host="127.0.0.1", port=1863, timeout=1.0):
    """Attempts to connect to a host/port, returns 'Online', 'Offline', or 'Error'."""
    status = "Offline" # Default status
    sock = None
    try:
        # Create socket and set timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # Attempt connection (connect_ex returns 0 on success)
        result = sock.connect_ex((host, port))
        if result == 0:
            status = "Online"
        # else: status remains "Offline" (includes connection refused, timeout)
    except socket.gaierror: # getaddrinfo error
        status = f"Error (Hostname?"
    except socket.error as e:
        # Catch other potential socket errors
        status = f"Error ({type(e).__name__})"
        print(f"ADMIN_GUI: Socket error checking {host}:{port} - {e}", file=sys.stderr)
    finally:
        # Ensure socket is closed
        if sock:
            sock.close()
    return status


# --- Login Route ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.username.data == ADMIN_USERNAME and form.password.data == ADMIN_PASSWORD:
            user = AdminUser('admin')
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index_page'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html', form=form)

# --- Logout Route ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

# --- Main Page Route ---
@app.route('/', methods=['GET'])
def index_page():
    # login_required handles authentication
    
    # Check MSN service status
    msn_status = check_service_status(host="127.0.0.1", port=1863) # Check internal port 1863

    users_list = []
    try:
        conn = Conn(settings.DB)
        with conn.session() as sess:
            users_data = sess.query(
                User.email, User.username, User.friendly_name, User.verified,
                User.date_created, User.date_login
            ).order_by(User.email).all()
            users_list = [dict(zip(['email', 'username', 'friendly_name', 'verified', 'date_created', 'date_login'], u)) for u in users_data]
    except Exception as e:
        flash(f'Error loading user list: {str(e)}', 'error')
        print(f"ADMIN_GUI: Error loading users: {str(e)}", file=sys.stderr)
    
    # Pass status and other data to template
    return render_template(
        'manage_users.html', 
        users=users_list, 
        client_versions=CLIENT_REG_CONFIGS.keys(),
        msn_status=msn_status # Pass the status here
    )

# --- Create User Action ---
@app.route('/create_user', methods=['POST'])
@login_required
def handle_create_user():
    # ... (logic from previous version remains the same) ...
    # login_required handles authentication
    email = request.form.get('email', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    friendly_name = request.form.get('friendly_name', '').strip() or username
    support_old_msn = request.form.get('oldmsn') == 'true'
    support_yahoo = request.form.get('yahoo') == 'true'
    verified_user = request.form.get('verified') == 'true'

    if not email or not username or not password:
        flash('Email, Username, and Password are required!', 'error')
    else:
        try:
            conn = Conn(settings.DB)
            with conn.session() as sess:
                if sess.query(User).filter(User.email == email).first():
                    flash(f'Error: Email "{email}" already exists.', 'error')
                elif sess.query(User).filter(User.username == username).first():
                    flash(f'Error: Username "{username}" already exists.', 'error')
                else:
                    print(f"ADMIN_GUI: Creating new user '{username}' with email '{email}'")
                    new_user = User(
                        uuid=misc.gen_uuid(), email=email, username=username, verified=verified_user,
                        friendly_name=friendly_name, message="", groups={}, settings={}
                    )
                    set_passwords(new_user, password, support_old_msn=support_old_msn, support_yahoo=support_yahoo)
                    sess.add(new_user)
                    sess.commit()
                    flash(f'User "{username}" ({email}) created successfully!', 'success')
        except Exception as e:
            flash(f'An server-side error occurred during creation: {str(e)}', 'error')
            print(f"ADMIN_GUI: Error creating user '{username}': {str(e)}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
    return redirect(url_for('index_page'))

# --- Edit User Page Route ---
@app.route('/edit_user/<user_email>', methods=['GET', 'POST'])
@login_required
def edit_user_page(user_email):
    # ... (logic from previous version remains the same) ...
    # login_required handles authentication
    conn = Conn(settings.DB)
    user_data_for_template = None

    if request.method == 'POST':
        # ... (password update logic) ...
        new_password = request.form.get('new_password', '')
        support_old_msn = request.form.get('oldmsn') == 'true'
        support_yahoo = request.form.get('yahoo') == 'true'
        if not new_password:
            flash('New Password cannot be empty!', 'error')
        else:
            try:
                with conn.session() as sess:
                    user_to_update = sess.query(User).filter(User.email == user_email).first()
                    if not user_to_update:
                        flash(f'Error: User with email "{user_email}" not found.', 'error')
                        return redirect(url_for('index_page'))
                    else:
                        print(f"ADMIN_GUI: Updating password for user '{user_to_update.username}' ({user_email})")
                        set_passwords(user_to_update, new_password, support_old_msn=support_old_msn, support_yahoo=support_yahoo)
                        sess.add(user_to_update)
                        sess.commit()
                        flash(f'Password for user "{user_to_update.username}" updated successfully!', 'success')
                        return redirect(url_for('index_page'))
            except Exception as e:
                flash(f'An server-side error occurred during password update: {str(e)}', 'error')
                print(f"ADMIN_GUI: Error updating password for '{user_email}': {str(e)}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)

    # GET Request part
    try:
        with conn.session() as sess:
            user = sess.query(User).filter(User.email == user_email).first()
            if not user:
                flash(f'User with email "{user_email}" not found.', 'error')
                return redirect(url_for('index_page'))
            user_data_for_template = {
                'email': user.email, 'username': user.username, 'friendly_name': user.friendly_name,
                'verified': user.verified,
                'supports_old_msn': bool(user.get_front_data('msn', 'pw_md5')),
                'supports_yahoo': bool(user.get_front_data('ymsg', 'pw_md5_unsalted') or user.get_front_data('ymsg', 'pw_md5crypt'))
            }
    except Exception as e:
         flash(f'Error loading user data for editing: {str(e)}', 'error')
         print(f"ADMIN_GUI: Error loading user '{user_email}' for edit: {str(e)}", file=sys.stderr)
         return redirect(url_for('index_page'))
    return render_template('edit_user.html', user=user_data_for_template)

# --- Delete User Action ---
@app.route('/delete_user', methods=['POST'])
@login_required
def handle_delete_user():
    # ... (logic from previous version remains the same - Basic Deletion) ...
    # login_required handles authentication
    email = request.form.get('email', '').strip()
    if not email:
        flash('Email is required to delete a user!', 'error')
    else:
        try:
            conn = Conn(settings.DB)
            with conn.session() as sess:
                user = sess.query(User).filter(User.email == email).first()
                if not user:
                    flash(f'Error: User with email "{email}" not found for deletion.', 'error')
                else:
                    username_to_delete = user.username
                    print(f"ADMIN_GUI: Deleting user '{username_to_delete}' ({email})")
                    sess.delete(user)
                    sess.commit()
                    flash(f'User "{username_to_delete}" ({email}) deleted. (Basic deletion).', 'success')
        except Exception as e:
            flash(f'An server-side error occurred during deletion: {str(e)}', 'error')
            print(f"ADMIN_GUI: Error deleting user '{email}': {str(e)}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
    return redirect(url_for('index_page'))

# --- Generate Registry File Route ---
@app.route('/generate_reg', methods=['POST'])
@login_required
def handle_generate_reg():
    # ... (logic from previous version remains the same) ...
    # login_required handles authentication
    client_version = request.form.get('client_version')
    server_ip = request.form.get('server_ip', '').strip()

    if not client_version or not server_ip:
        flash("Client version and Server IP are required to generate a .reg file.", "error")
        return redirect(url_for('index_page'))
    if client_version not in CLIENT_REG_CONFIGS:
        flash(f"Invalid client version selected: {client_version}", "error")
        return redirect(url_for('index_page'))
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server_ip) and not re.match(r"^[a-zA-Z0-9.-]+$", server_ip):
         flash(f"Invalid Server IP format: {server_ip}", "error")
         return redirect(url_for('index_page'))

    config = CLIENT_REG_CONFIGS[client_version]
    reg_path = config['path']
    keys = config['keys']
    reg_content = "Windows Registry Editor Version 5.00\r\n\r\n"
    reg_content += f"[HKEY_CURRENT_USER\\{reg_path}]\r\n"
    for key_name, (key_type, value_template) in keys.items():
        if key_type == "DELETE":
            reg_content += f"\"{key_name}\"=-\r\n"
        elif key_type == "REG_SZ":
            value = str(value_template).format(server_ip=server_ip)
            escaped_value = value.replace('\\', '\\\\').replace('"', '\\"')
            reg_content += f"\"{key_name}\"=\"{escaped_value}\"\r\n"
        elif key_type == "REG_DWORD":
            value = int(value_template)
            hex_value = f"{value:08x}"
            reg_content += f"\"{key_name}\"=dword:{hex_value}\r\n"
    reg_content += "\r\n"
    safe_client_version = re.sub(r'[^\w.-]+', '_', client_version)
    filename = f"escargot_patch_{safe_client_version}.reg"
    return Response(
        reg_content, mimetype='text/plain',
        headers={'Content-Disposition': f'attachment;filename={filename}'}
    )

# --- Main execution ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)