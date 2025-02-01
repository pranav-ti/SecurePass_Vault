import sqlite3
import bcrypt
import os
import random
import string
from getpass import getpass

DB_PATH = os.getenv("DB_PATH", "data/password_vault.db")

SECURITY_QUESTIONS = [
    "What is your mother's maiden name?",
    "What was the name of your first pet?",
    "What city were you born in?",
    "What is the name of your favorite teacher?",
    "What is your favorite movie?"
]

def initialize_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Drops the old credentials table if it already exists
        cursor.execute('DROP TABLE IF EXISTS credentials')
        conn.commit()
        
        # Creates a new table if it don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                website TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                security_question TEXT NOT NULL,
                security_answer_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

def set_master_password():
    password = getpass("Set a master password: ").encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO master_password (id, password_hash) VALUES (1, ?)", (hashed,))
        conn.commit()
    print("Master password set successfully!")

def verify_master_password():
    password = getpass("Enter master password: ").encode('utf-8')
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM master_password WHERE id=1")
        stored_hash = cursor.fetchone()
    
    if stored_hash and bcrypt.checkpw(password, stored_hash[0]):
        print("Access Granted!")
        return True
    else:
        print("Access Denied!")
        return False

def add_credential():
    website = input("Enter the website URL: ").strip()
    username = input("Enter the username: ").strip()
    password = getpass("Enter the password: ").encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    
    # Displays the security questions for the user to choose from
    print("\nChoose a security question:")
    for i, question in enumerate(SECURITY_QUESTIONS, 1):
        print(f"{i}. {question}")
    
    choice = input("Enter the number of your chosen security question: ").strip()
    while not choice.isdigit() or int(choice) < 1 or int(choice) > len(SECURITY_QUESTIONS):
        print("Invalid choice. Please try again.")
        choice = input("Enter the number of your chosen security question: ").strip()
    
    security_question = SECURITY_QUESTIONS[int(choice) - 1]
    security_answer = getpass("Answer the question: ").encode('utf-8')
    hashed_answer = bcrypt.hashpw(security_answer, bcrypt.gensalt())

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO credentials 
            (website, username, password_hash, security_question, security_answer_hash) 
            VALUES (?, ?, ?, ?, ?)
        """, (website, username, hashed_password, security_question, hashed_answer))
        conn.commit()
    print("Credential added/updated successfully!")

def get_credential():
    website = input("Enter the website URL to retrieve credentials: ").strip()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, password_hash, security_question, security_answer_hash 
            FROM credentials WHERE website=?
        """, (website,))
        result = cursor.fetchone()
    
    if result:
        username, hashed_password, security_question, stored_answer_hash = result
        print(f"Username: {username}")
        
        show_password = input("Do you want to see the password? (yes/no): ").strip().lower()
        if show_password == 'yes':
            print(f"Security Question: {security_question}")
            answer = getpass("Your answer: ").encode('utf-8')
            if bcrypt.checkpw(answer, stored_answer_hash):
                print("Correct! Here’s your password:")
                password = getpass("Re-enter your password to confirm: ").encode('utf-8')
                if bcrypt.checkpw(password, hashed_password):
                    print(f"Your password is: {password.decode('utf-8')}")
                else:
                    print("Incorrect password. Access denied.")
            else:
                print("Oops! Wrong answer. Access denied.")
        else:
            print("Okay, you don't need the password.")
    else:
        print("No credentials found for this website.")

def delete_credential():
    website = input("Enter the website URL to delete: ").strip()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE website=?", (website,))
        conn.commit()
    print(f"Credential for {website} deleted successfully!")

def check_password_strength(password):
    # Password strength criteria:
    length = len(password) >= 12
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    common_passwords = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome']
    is_common = password.lower() in common_passwords
    
    score = 0
    feedback = []
    
    if length:
        score += 1
    else:
        feedback.append("Password should be at least 12 characters long.")
    
    if has_upper and has_lower:
        score += 1
    else:
        feedback.append("Password should include both uppercase and lowercase letters.")
    
    if has_digit:
        score += 1
    else:
        feedback.append("Password should contain at least one digit.")
    
    if has_special:
        score += 1
    else:
        feedback.append("Password should include at least one special character.")
    
    if is_common:
        score = 0
        feedback.append("Password is too common and easily guessable.")
    
    strength = "Weak"
    if score >= 4 and not is_common:
        strength = "Strong"
    elif score >= 2:
        strength = "Moderate"
    
    return strength, feedback

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    while True:
        password = ''.join(random.choice(characters) for _ in range(length))
        if (any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(not c.isalnum() for c in password)):
            return password

def menu():
    while True:
        print("\n--- Password Vault Menu ---")
        print("1. Add/Update credential")
        print("2. Retrieve credential")
        print("3. Delete credential")
        print("4. Check password strength")
        print("5. Exit")
        choice = input("\nChoose an option: ").strip()
        
        print("\n" + "="*30)

        if choice == "1":
            add_credential()
        elif choice == "2":
            get_credential()
        elif choice == "3":
            delete_credential()
        elif choice == "4":
            password = getpass("Enter a password to check its strength: ").strip()
            strength, feedback = check_password_strength(password)
            print(f"\nPassword Strength: {strength}")
            if strength in ["Weak", "Moderate"]:
                print("Feedback:")
                for item in feedback:
                    print(f"- {item}")
                suggestion = generate_strong_password()
                print(f"\nSuggested strong password: {suggestion}")
            else:
                print("Your password is strong! Great job!")
        elif choice == "5":
            print("\nExiting... Goodbye!")
            break
        else:
            print("\nInvalid choice, please try again.\n")

initialize_db()
with sqlite3.connect(DB_PATH) as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM master_password")
    if cursor.fetchone() is None:
        set_master_password()

if verify_master_password():
    menu()