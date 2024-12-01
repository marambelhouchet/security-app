from flask import Flask, render_template, request, redirect, url_for, session
import pg8000
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import secrets
import base64
import hashlib
import requests
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import check_password_hash, generate_password_hash
from PIL import Image
import io
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
app = Flask(__name__)

# PostgreSQL database configuration
DATABASE_URL = "postgresql://postgres:DUsNwtpUKvJdToEzIrgIDoBMIYHXjZlZ@junction.proxy.rlwy.net:12055/railway"

# reCAPTCHA keys
RECAPTCHA_SITE_KEY = "6LctTXwqAAAAAE6EthQjtgeHPoMhhXVNrr6tl40b"
RECAPTCHA_SECRET_KEY = "6LctTXwqAAAAALxiBM5HV5SHg2IAL2q47ZBzxPrL"

# Secret key for session management
app.secret_key = secrets.token_hex(16)  # Secure random string

# Database connection
def get_db_connection():
    parts = DATABASE_URL.replace("postgresql://", "").split("@")
    user_pass, host_db = parts[0], parts[1]
    user, password = user_pass.split(":")
    host, db = host_db.split("/")
    hostname, port = host.split(":")
    conn = pg8000.connect(user=user, password=password, host=hostname, port=int(port), database=db)
    return conn


# reCAPTCHA verification
def verify_recaptcha(response_token):
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': response_token
    }
    verification_response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
    return verification_response.json().get('success', False)


# AES Encryption/Decryption using ECB mode
def aes_encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext


def aes_decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode()

KEK = hashlib.sha256(b"secure_password_for_kek").digest()
# Generate AES key based on length
def generate_aes_key(key_length):
    if key_length not in [128, 192, 256]:
        raise ValueError("Invalid key length. Must be 128, 192, or 256 bits.")
    return os.urandom(key_length // 8)
# This will be used to encrypt/decrypt keys securely
def derive_key_from_password(password):
    """ Derive a key from a password using PBKDF2 HMAC """
    salt = b'some_salt'  # Use a static or user-specific salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Key derivation function
        length=32,                  # Output key length
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

# Key Vault Route
@app.route('/key_vault', methods=['GET', 'POST'])
def key_vault():
    if 'username' not in session:
        return redirect(url_for('signin'))

    message = None
    stored_key = None

    if request.method == 'POST':
        action = request.form.get('action')

        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        if action == 'save':
            secret_name = request.form.get('secret_name')
            secret_value = request.form.get('secret_value')
            if secret_name and secret_value:
                try:
                    # Fetch the logged-in user's password
                    cursor.execute("SELECT password FROM users WHERE username = %s", (session['username'],))
                    row = cursor.fetchone()

                    if row:
                        stored_password = row[0]
                        derived_key = derive_key_from_password(stored_password)

                        # Encrypt and store the key
                        encrypted_key = aes_encrypt(secret_value, derived_key)
                        cursor.execute(
                            """
                            INSERT INTO key_vault (username, secret_name, encrypted_key)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (username, secret_name)
                            DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key
                            """,
                            (session['username'], secret_name, encrypted_key)
                        )
                        conn.commit()
                        message = "Secret saved successfully!"
                    else:
                        message = "User does not exist."
                except Exception as e:
                    message = f"Error saving secret: {e}"

        elif action == 'retrieve':
            secret_name = request.form.get('secret_name')
            password = request.form.get('password')
            if not password or not secret_name:
                message = "Password and secret name are required to retrieve the secret."
            else:
                try:
                    # Verify user's password
                    cursor.execute("SELECT password FROM users WHERE username = %s", (session['username'],))
                    row = cursor.fetchone()

                    if row:
                        stored_password = row[0]
                        if password == stored_password:
                            # Fetch the encrypted key by secret name
                            cursor.execute(
                                "SELECT encrypted_key FROM key_vault WHERE username = %s AND secret_name = %s",
                                (session['username'], secret_name)
                            )
                            row = cursor.fetchone()

                            if row:
                                encrypted_key = row[0]
                                derived_key = derive_key_from_password(password)
                                stored_key = aes_decrypt(encrypted_key, derived_key)
                            else:
                                message = "No secret found with that name for this user."
                        else:
                            message = "Incorrect password."
                    else:
                        message = "User does not exist."
                except Exception as e:
                    message = f"Error retrieving secret: {e}"

        cursor.close()
        conn.close()

    return render_template('key_vault.html', message=message, stored_key=stored_key)



@app.route('/matrix', methods=['GET', 'POST'])
def matrix_encryption():
    if 'username' not in session:
        return redirect(url_for('signin'))

    encrypted_matrix = None
    decrypted_matrix = None

    # Get matrix dimensions and Caesar cipher shift value from form or set defaults
    rows = int(request.form.get('rows', 3))  # Default to 3 rows
    cols = int(request.form.get('cols', 3))  # Default to 3 columns
    shift = int(request.form.get('shift', 3))  # Default to 3 for Caesar cipher shift

    # Collect the matrix values
    if request.method == 'POST':
        matrix_data = [
            [request.form.get(f"cell_{r}_{c}") for c in range(cols)] 
            for r in range(rows)
        ]

        action = request.form.get('action')
        if action == 'encrypt':
            # Apply Caesar cipher encryption on each element of the matrix
            encrypted_matrix = [
                [caesar_encrypt(cell, shift) for cell in row] for row in matrix_data
            ]
        elif action == 'decrypt':
            # Apply Caesar cipher decryption on each element of the matrix
            decrypted_matrix = [
                [caesar_decrypt(cell, shift) for cell in row] for row in matrix_data
            ]

    return render_template(
        'matrix.html',
        encrypted_matrix=encrypted_matrix,
        decrypted_matrix=decrypted_matrix,
        rows=rows,
        cols=cols,
        shift=shift
    )

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('signin'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch logs from the database
    cursor.execute("SELECT username, event_type, event_message, created_at FROM logs ORDER BY created_at DESC")
    logs = cursor.fetchall()

    # Fetch all users from the database
    cursor.execute("SELECT username, role FROM users")
    all_users = cursor.fetchall()

    # Fetch only the message column for messages sent to the admin
    cursor.execute("SELECT id, sender, message, encrypted_dek, created_at FROM messages WHERE receiver = %s ORDER BY created_at DESC", ('admin',))
    admin_messages = cursor.fetchall()

    # Handle decryption logic
    decrypted_messages = []
    message_error = None

    if request.method == 'POST':
        # Handling sending a message
        message_text = request.form.get('message')  # Admin message to send
        receiver = request.form.get('receiver')  # Receiver of the message
        password = request.form.get('password')  # Admin input for decryption password
        
        # If there's a message and a receiver, proceed with encryption and insertion into the database
        if message_text and receiver:
            try:
                # Generate a DEK for the message
                dek = generate_dek()  # This should be a function to generate a random DEK
                
                # Encrypt the DEK using the KEK (Key Encryption Key)
                encrypted_dek = encrypt_dek(dek)  # This should use the admin's KEK to encrypt the DEK
                
                # Encrypt the message using the DEK
                encrypted_message = aes_encrypt(message_text, dek)  # AES encryption of the message using the DEK

                # Insert the encrypted message and DEK into the database
                created_at = datetime.now()
                cursor.execute("""
                    INSERT INTO messages (sender, receiver, message, encrypted_dek, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                """, (session['username'], receiver, encrypted_message, encrypted_dek, created_at))
                conn.commit()

                # Optionally, you can send a success message or perform other actions after insertion
                message_error = "Message sent successfully."

            except Exception as e:
                message_error = f"Message sending failed: {e}"

        # If a password is entered, attempt decryption for the admin's view of messages
        if password:
            try:
                # Hash password to derive the KEK and attempt decryption
                password_kek = hashlib.sha256(password.encode()).digest()

                for message_id, sender, encrypted_message, encrypted_dek, created_at in admin_messages:
                    # Decrypt the DEK using the KEK
                    dek = decrypt_dek(encrypted_dek)  # Decrypt the DEK with the KEK
                    decrypted_message = aes_decrypt(encrypted_message, dek)  # Decrypt the message with the DEK
                    decrypted_messages.append((sender, decrypted_message, created_at))

                # Update the admin messages with decrypted data
                admin_messages = decrypted_messages

            except Exception as e:
                message_error = f"Decryption failed: {e}"

    cursor.close()
    conn.close()

    return render_template(
        'admin_dashboard.html',
        logs=logs,
        all_users=all_users,
        admin_messages=admin_messages,  # Display the decrypted messages
        message_error=message_error      # Pass error if decryption fails
    )

# Encrypt data using AES and a given key
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(ciphertext).decode()

# Decrypt data using AES and a given key
def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted.decode()

# Generate a DEK (Data Encryption Key)
def generate_dek():
    return os.urandom(16)  # 128-bit DEK

# Encrypt DEK using KEK
def encrypt_dek(dek):
    return aes_encrypt(dek.hex(), KEK)

# Decrypt DEK using KEK
def decrypt_dek(encrypted_dek):
    dek_hex = aes_decrypt(encrypted_dek, KEK)
    return bytes.fromhex(dek_hex)

@app.route('/encrypt/aes', methods=['GET', 'POST'])
def aes_encrypt_route():
    if 'username' not in session:
        return redirect(url_for('signin'))

    encrypted_text = None
    decrypted_text = None
    generated_key = None
    message = None

    if request.method == 'POST':
        action = request.form.get('action')
        key_length = int(request.form.get('key_length', 128))  # Default to 128-bit
        text = request.form.get('text', '').strip()

        try:
            # Generate a new AES key only if it is not already set in the session
            if 'aes_key' not in session:
                generated_key = generate_aes_key(key_length)
                session['aes_key'] = generated_key  # Store the key in the session for decryption
            
            # Handle encryption
            if action == 'encrypt' and text:
                encrypted_bytes = aes_encrypt_ecb(text, session['aes_key'])
                encrypted_text = encrypted_bytes.hex()  # Convert to hex for display

            # Handle decryption
            elif action == 'decrypt':
                encrypted_text_input = request.form.get('encrypted_text')
                if encrypted_text_input:
                    encrypted_bytes = bytes.fromhex(encrypted_text_input)
                    decrypted_text = aes_decrypt_ecb(encrypted_bytes, session['aes_key'])
                else:
                    message = "Please enter valid encrypted text to decrypt."

        except Exception as e:
            message = f"Error: {str(e)}"

    return render_template(
        'aes.html',
        encrypted_text=encrypted_text,
        decrypted_text=decrypted_text,
        key=session.get('aes_key', None).hex() if 'aes_key' in session else None,
        message=message
    )

# Caesar Cipher Encryption/Decryption
def caesar_encrypt(text, shift):
    return ''.join(chr((ord(char) - 32 + shift) % 95 + 32) for char in text)


def caesar_decrypt(text, shift):
    return ''.join(chr((ord(char) - 32 - shift) % 95 + 32) for char in text)


# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        recaptcha_response = request.form.get('g-recaptcha-response')
        role = request.form.get('role', 'user')  # Default to 'user'

        if not username or not password:
            message = "Username and password are required."
        elif not recaptcha_response or not verify_recaptcha(recaptcha_response):
            message = "reCAPTCHA verification failed. Please try again."
        else:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                created_at = datetime.now()
                query = """
                    INSERT INTO users (username, password, created_at, role)
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(query, (username, password, created_at, role))
                conn.commit()
                cursor.close()
                conn.close()
                return redirect(url_for('signin'))
            except Exception as e:
                message = f"An error occurred: {e}"

    return render_template('signup.html', message=message, recaptcha_site_key=RECAPTCHA_SITE_KEY)


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    message = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not username or not password:
            message = "Username and password are required."
        elif not recaptcha_response or not verify_recaptcha(recaptcha_response):
            message = "reCAPTCHA verification failed. Please try again."
        else:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                query = "SELECT * FROM users WHERE username = %s AND password = %s"
                cursor.execute(query, (username, password))
                user = cursor.fetchone()
                cursor.close()
                conn.close()

                if user:
                    session['username'] = username
                    session['role'] = user[4]  

                    # Redirect based on the user's role
                    if session['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('home', username=username))
                else:
                    message = "Invalid username or password."
            except Exception as e:
                message = f"An error occurred: {e}"

    return render_template('signin.html', message=message, recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('signin'))
    
    message = None
    if request.method == 'POST':
        receiver = request.form.get('receiver')
        message_text = request.form.get('message')
        
        if receiver and message_text:
            try:
                # Generate a DEK for the message
                dek = generate_dek()
                
                # Encrypt the DEK using the KEK (Key Encryption Key)
                encrypted_dek = encrypt_dek(dek)
                
                # Encrypt the message using the DEK
                encrypted_message = aes_encrypt(message_text, dek)

                # Store encrypted message and DEK in the database
                conn = get_db_connection()
                cursor = conn.cursor()
                created_at = datetime.now()
                
                query = """
                    INSERT INTO messages (sender, receiver, message, encrypted_dek, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(query, (session['username'], receiver, encrypted_message, encrypted_dek, created_at))
                conn.commit()
                cursor.close()
                conn.close()
                
                message = "Message sent successfully."
            except Exception as e:
                message = f"An error occurred: {e}"
    return render_template('home.html', username=session['username'], message=message)


# Define the upload folder and allowed extensions
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_image', methods=['GET', 'POST'])
def upload_image():
    if 'username' not in session:
        return redirect(url_for('signin'))

    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If no file is selected
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)  # Save the file
            flash('File uploaded successfully!')
            return render_template('upload_image.html', filename=filename)
    
    return render_template('upload_image.html')



@app.route('/view_messages/<username>', methods=['GET', 'POST'])
def view_messages(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('signin'))
    
    messages = []
    decrypted_messages = []
    error = None
    message_error = None

    try:
        # Fetch messages from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "SELECT sender, message, encrypted_dek, created_at FROM messages WHERE receiver = %s ORDER BY created_at DESC"
        cursor.execute(query, (username,))
        messages = cursor.fetchall()
        cursor.close()
        conn.close()
    except Exception as e:
        error = str(e)

    if request.method == 'POST':
        password = request.form.get('password')  # Get password input for decryption

        if password:
            try:
                # Hash password to derive the KEK (Key Encryption Key) and attempt decryption
                password_kek = hashlib.sha256(password.encode()).digest()

                for sender, encrypted_message, encrypted_dek, created_at in messages:
                    # Decrypt the DEK using the KEK (Key Encryption Key)
                    dek = decrypt_dek(encrypted_dek)

                    # Decrypt the message using the DEK
                    decrypted_message = aes_decrypt(encrypted_message, dek)

                    decrypted_messages.append((sender, decrypted_message, created_at))

            except Exception as e:
                message_error = f"Decryption failed: {e}"

    return render_template(
        'view_messages.html',
        username=username,
        messages=messages,  # Show the encrypted messages (before decryption)
        decrypted_messages=decrypted_messages,  # Show decrypted messages (after password decryption)
        error=error,
        message_error=message_error  # Pass the decryption error message if any
    )


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('signin'))
@app.route('/encrypt/caesar', methods=['GET', 'POST'])
def caesar_encrypt_route():
    if 'username' not in session:
        return redirect(url_for('signin'))

    encrypted_text = None
    decrypted_text = None

    if request.method == 'POST':
        text = request.form.get('text')
        action = request.form.get('action')

        if action == 'encrypt':
            encrypted_text = caesar_encrypt(text, 3)
        elif action == 'decrypt':
            encrypted_text_input = request.form.get('encrypted_text')
            if encrypted_text_input:
                decrypted_text = caesar_decrypt(encrypted_text_input, 3)

    return render_template('caesar.html', encrypted_text=encrypted_text, decrypted_text=decrypted_text)


if __name__ == "__main__":
    app.run(debug=True)