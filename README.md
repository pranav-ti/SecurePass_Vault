# 🔒 SecurePass Vault  
*A secure password manager with encryption and password strength analysis*

## Features
- 🔐 **Master Password Protection**: Uses bcrypt hashing for secure authentication
- 🔄 **Credential Management**: Store, update, retrieve, and delete website credentials
- ❓ **Security Questions**: Choose from 5 predefined security questions for account recovery
- 💪 **Password Strength Checker**: Analyzes password quality and suggests improvements
- 🛡️ **Encryption**: All sensitive data is hashed with bcrypt
- 📁 **SQLite Database**: Local and encrypted storage for credentials

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/pranav-ti/password_vault.git
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. **Usage**

    ```bash
    python vault.py
    ```

**Menu Options:**

    1. Add/Update credentials for a website
    
    2. Retrieve stored credentials
    
    3. Delete credentials
    
    4. Check password strength
    
    5. Exit


**Security Notes**

    Never share your master password
    
    Database is stored locally at data/password_vault.db
    
    All passwords and security answers are hashed using bcrypt
