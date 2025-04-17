

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

#data information of user

DATA_FILE = "secure_data.json"
SALTS = b"secure_salt_data"
LOCKOUT_DURATION = 60  # seconds


#Section login details

if "authenticated" not in st.session_state:
    st.session_state.authenticated = None
    

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

#Function to load and save data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


def generate_key(password, salt=SALTS):
    key=pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return urlsafe_b64encode(key)
def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), SALTS, 100000).hex()
#cryptography.fernet used
def encrypt_data(text, key):
    cipher = Fernet( generate_key (key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except :
        return None 

stored_data = load_data()
#navigation bar
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("Devlop a stremlit app to **securely store and retrieve data** using unique passkeys .")
#user registration
elif choice == "Register":
    st.subheader("🔑 Register a New User")
    username = st.text_input("Enter your username:")
    password = st.text_input("Enter your password:", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_passkey(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ Registration successful!")
        else:
            st.error("⚠️ Both fields are required!")



elif choice == "Login":
    st.subheader("🔑 Login")
    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f"❌ Too many failed attempts! Please wait {remaining_time} seconds.")
        st.stop()
    username = st.text_input("Enter your username:")
    password = st.text_input("Enter your password:", type="password")
    
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_passkey(password):
            st.session_state.authenticated = username
            st.session_state.failed_attempts = 0
            st.success(f"welcome {username} !")
        else:
            st.session_state.failed_attempts += 1
            # remaining_time = 3 - st.session_state.failed_attempts
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ invalid Creadentials! Attempts Left: {attempts_left}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts! You are locked out for 60 seconds.")
                st.stop()
#Data stred section
elif choice == "Store Data":
    if not st.session_state.authenticated:
        st.warning("⚠️ Please login First.")
    else:
        st.subheader("📂 Store Encryped Data")
        user_data = st.text_area("Enter dat to  Encryped:")
        passkey = st.text_input("Enter a unique passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                encrypt_result = encrypt_data(user_data, passkey)
                stored_data[st.session_state.authenticated]["data"].append(encrypt_result)
                save_data(stored_data)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ All fields are required to fill!")

#Data retrival section
elif choice == "Retrieve Data":
    if not st.session_state.authenticated:
        st.warning("⚠️ Please login First.")
    else:
        st.subheader("🔑 Retrieve Your Data")
        user_data = stored_data.get(st.session_state.authenticated, {}).get("data", [])

        if not user_data:
           st.info("No data found for the user.")
        else:
            st.write("Encryped Data Entries:")
            for i , item in enumerate(user_data):
                st.code(item, language="text")
            encrypt_input = st.text_input("Enter the encrypted data to decrypt:")
            passkey = st.text_input("Enter your passkey:", type="password")
            if st.button("Decrypt"):
                result = decrypt_text(encrypt_input, passkey)
                if result:
                    st.success(f"Decrypted Data: {result}")
                else:
                    st.error("❌ Incorrect passkey or invalid encrypted data!")




