import sqlite3

# --- Connect to the database ---
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# --- Create a table if it doesn't already exist ---
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

# --- Optional: Sanitize input ---
def sanitize_input(input_str):
    """
    Basic sanitation: trims spaces, removes dangerous SQL characters.
    Note: This is a safety layer, not a replacement for parameterized queries.
    """
    return input_str.strip().replace(";", "").replace("--", "").replace("'", "").replace("\"", "")

# --- Safe function to insert data ---
def insert_user(username, password):
    username = sanitize_input(username)
    password = sanitize_input(password)

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    print("✅ User inserted successfully.")

# --- Safe function to authenticate user ---
def authenticate(username, password):
    username = sanitize_input(username)
    password = sanitize_input(password)

    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    result = cursor.fetchone()
    if result:
        print("🔐 Login successful!")
    else:
        print("❌ Invalid username or password.")

# --- Example usage ---
insert_user("admin", "1234")
authenticate("admin", "1234")          # ✅ Success
authenticate("admin'; --", "1234")     # ❌ Fails (SQL injection attempt blocked)

# --- Close connection ---
conn.close()
