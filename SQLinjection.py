import sqlite3
import logging
from getpass import getpass
import re

# 🧠 1. MONITORING DATABASE ACTIVITY
logging.basicConfig(filename="db_activity.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# 🔒 DATABASE CONNECTION
conn = sqlite3.connect("secure_system.db")
cursor = conn.cursor()

# 🛠️ CREATE TABLE (if not exists)
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
""")
conn.commit()

# 🧽 2. SANITIZE INPUTS (basic example)
def sanitize_input(text):
    return re.sub(r"[^\w@.-]", "", text)  # allow alphanumeric, underscore, dot, dash, @

# 🔏 5. ACCESS CONTROL BASED ON ROLE
def has_access(username, required_role):
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    return result and result[0] == required_role

# ➕ CREATE USER (admin-only)
def create_user(admin_user):
    if not has_access(admin_user, "admin"):
        print("Access denied: Admin role required.")
        return

    username = sanitize_input(input("New username: "))
    password = getpass("New password: ")
    role = sanitize_input(input("Role (admin/user): ").lower())

    try:
        # ✅ 3. PREPARED STATEMENT + 1. PARAMETERIZED QUERY
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        logging.info(f"[{admin_user}] Created new user: {username}")
        print("User created successfully.")
    except sqlite3.IntegrityError:
        print("Error: Username already exists.")

# 🔐 LOGIN FUNCTION
def authenticate():
    username = sanitize_input(input("Username: "))
    password = getpass("Password: ")

    # ✅ 1. PARAMETERIZED QUERY (in prepared statement style)
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()

    if user:
        logging.info(f"[{username}] Successfully logged in.")
        print(f"Welcome, {username}!")
        return username
    else:
        print("Login failed: Invalid credentials.")
        return None

# MAIN
if __name__ == "__main__":
    print("🔐 Secure Login System")
    user = authenticate()

    if user:
        action = input("Do you want to (c)reate new user or (e)xit? ").strip().lower()
        if action == "c":
            create_user(user)
        else:
            print("Exiting...")

    conn.close()
