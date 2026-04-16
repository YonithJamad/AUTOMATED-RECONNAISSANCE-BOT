import sqlite3
import os
import argparse
import getpass
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "users.db")

def add_user(username, password):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        
        # Ensure the table exists even if app.py hasn't been run yet
        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute("INSERT INTO user_details (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print(f"[+] Successfully added user '{username}' to the database.")
    except sqlite3.IntegrityError:
        print(f"[-] Error: Username '{username}' already exists.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add a new user to the login application database.")
    parser.add_argument("-u", "--username", help="Username to add", required=False)
    
    args = parser.parse_args()
    
    username = args.username
    if not username:
        username = input("Enter new username: ")
        
    password = getpass.getpass("Enter password for user (will be hidden): ")
    
    if not username or not password:
        print("[-] Username and password cannot be empty.")
    else:
        add_user(username, password)
