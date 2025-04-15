import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64
import secrets
import string
from datetime import datetime, timedelta
import json
import os

DATA_FILE = "data.json"
USERS_FILE = "users.json"

# Global "database"
if "users_db" not in st.session_state:
    st.session_state.users_db = {}

if "current_user" not in st.session_state:
    st.session_state.current_user = None

# Helper Functions
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    else:
        return {}

def save_users(users_data):
    with open(USERS_FILE, "w") as f:
        json.dump(users_data, f, indent=4)

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    else:
        return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def derive_fernet_key(passkey):
    key_hash = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)

def encrypt_data(plain_text, passkey):
    fernet_key = derive_fernet_key(passkey)
    f = Fernet(fernet_key)
    encrypted = f.encrypt(plain_text.encode())
    return encrypted.decode()

def decrypt_data(encrypted_text, passkey):
    fernet_key = derive_fernet_key(passkey)
    f = Fernet(fernet_key)
    try:
        decrypted = f.decrypt(encrypted_text.encode())
        return decrypted.decode(), True
    except InvalidToken:
        return None, False

def is_locked(user_record):
    lockout_until = user_record.get("lockout_until", None)
    if lockout_until and datetime.now() < lockout_until:
        return True, lockout_until
    if lockout_until:
        user_record["fail_count"] = 0
        user_record["lockout_until"] = None
    return False, None

def reset_failures(user_record):
    user_record["fail_count"] = 0
    user_record["lockout_until"] = None

def register_user(username, password):
    if username in st.session_state.users_db:
        return False, "Username already exists!"
    st.session_state.users_db[username] = {
        "password_hash": hash_text(password),
        "data": [],
        "fail_count": 0,
        "lockout_until": None
    }
    save_users(st.session_state.users_db)
    return True, "User registered successfully!"

def login_user(username, password):
    st.session_state.users_db = load_users()
    if username not in st.session_state.users_db:
        return False, "Username does not exist. Please register first."
    user_record = st.session_state.users_db[username]
    if hash_text(password) == user_record["password_hash"]:
        st.session_state.current_user = username
        reset_failures(user_record)
        return True, "Logged in successfully!"
    return False, "Incorrect password."

def add_data_for_user(username, encrypted_text):
    if username not in st.session_state.encrypted_data:
        st.session_state.encrypted_data[username] = []
    st.session_state.encrypted_data[username].append({
        "encrypted": encrypted_text,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    save_data(st.session_state.encrypted_data)

def generate_passkey(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def get_strength(passkey):
    score = 0
    if len(passkey) >= 8: score += 1
    if len(passkey) >= 12: score += 1
    if any(c.isdigit() for c in passkey): score += 1
    if any(c.islower() for c in passkey): score += 1
    if any(c.isupper() for c in passkey): score += 1
    if any(c in string.punctuation for c in passkey): score += 1
    return score

if "users_db" not in st.session_state:
    st.session_state.users_db = load_users()

if "encrypted_data" not in st.session_state:
    st.session_state.encrypted_data = load_data()

# Pages
def home_page():
    st.title("🔐 Secure Data Encryption System")
    if st.session_state.current_user:
        st.success(f"Welcome, **{st.session_state.current_user}** 👋")
        st.write("Choose an option from the sidebar.")
    else:
        st.info("Please register or login from the sidebar.")

def register_page():
    st.title("📝 Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and password:
            success, msg = register_user(username, password)
            st.info(msg)
            if success:
                st.session_state.current_user = username
        else:
            st.error("Username and password required.")

def login_page():
    st.title("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username and password:
            success, msg = login_user(username, password)
            if success:
                st.success(msg)
            else:
                st.error(msg)
        else:
            st.error("Please enter username and password.")

def insert_data_page():
    if st.session_state.current_user is None:
        st.warning("Please log in first.")
        return

    st.title("➕ Insert Data")
    data_text = st.text_area("Enter data to encrypt")

    # Passkey generation
    if "generated_passkey" not in st.session_state:
        st.session_state.generated_passkey = ""

    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Generate Passkey"):
            st.session_state.generated_passkey = generate_passkey()

    passkey = st.text_input("Enter or use generated passkey", 
                            type="password", 
                            value=st.session_state.generated_passkey, 
                            key="passkey_input")

    if passkey:
        strength = get_strength(passkey)

        st.write("### 🔐 Passkey Strength:")
        if strength <= 2:
            st.markdown("<span style='color: red;'>🔴 Weak – Try adding more characters, symbols, or numbers</span>", unsafe_allow_html=True)
            st.progress(strength / 6)
        elif strength <= 4:
            st.markdown("<span style='color: orange;'>🟠 Moderate – Could be stronger</span>", unsafe_allow_html=True)
            st.progress(strength / 6)
        else:
            st.markdown("<span style='color: green;'>🟢 Strong – Looks secure!</span>", unsafe_allow_html=True)
            st.progress(strength / 6)

    if st.button("Encrypt and Store Data"):
        if data_text and passkey:
            encrypted_text = encrypt_data(data_text, passkey)
            add_data_for_user(st.session_state.current_user, encrypted_text)
            st.success("Data encrypted and stored.")
            st.code(encrypted_text)
        else:
            st.error("Please enter both data and passkey.")

def retrieve_data_page():
    if st.session_state.current_user is None:
        st.warning("Please log in first.")
        return

    st.title("🔍 Retrieve Data")
    user_record = st.session_state.users_db[st.session_state.current_user]

    locked, until = is_locked(user_record)
    if locked:
        st.error(f"Locked until {until.strftime('%H:%M:%S')}")
        return

    encrypted_input = st.text_area("Paste your encrypted data")
    passkey = st.text_input("Enter passkey to decrypt", type="password")

    if st.button("Decrypt Data"):
        if passkey and encrypted_input:
            decrypted, success = decrypt_data(encrypted_input, passkey)
            if success:
                st.success("Data decrypted:")
                st.code(decrypted)
                reset_failures(user_record)
            else:
                user_record["fail_count"] += 1
                st.error(f"Incorrect passkey. Attempt #{user_record['fail_count']}")
                if user_record["fail_count"] >= 3:
                    user_record["lockout_until"] = datetime.now() + timedelta(minutes=1)
                    st.session_state.current_user = None
                    st.error("Too many failed attempts. You’ve been logged out.")
        else:
            st.warning("Provide encrypted text and passkey.")

def history_page():
    if st.session_state.current_user is None:
        st.warning("Please log in first.")
        return

    st.title("📜 Encrypted Data History")
    user_data = st.session_state.encrypted_data.get(st.session_state.current_user, [])

    if not user_data:
        st.info("No encrypted data stored yet.")
        return

    for i, item in enumerate(user_data):
        with st.expander(f"🔐 Entry {i+1} | {item['timestamp']}"):
            st.code(item["encrypted"])

# Navigation
st.sidebar.title("🔧 Menu")
page = st.sidebar.radio("Navigate", ["Home", "Register", "Login", "Insert Data", "Retrieve Data", "Encrypted History"])

if page == "Home": home_page()
elif page == "Register": register_page()
elif page == "Login": login_page()
elif page == "Insert Data": insert_data_page()
elif page == "Retrieve Data": retrieve_data_page()
elif page == "Encrypted History": history_page()

# Logout Button
if st.session_state.current_user:
    if st.sidebar.button("Logout"):
        st.session_state.current_user = None
        st.sidebar.success("Logged out successfully!")
