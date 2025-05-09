import sqlite3
import os
import base64
from .crypto import CryptoManager

class DatabaseManager:
    def __init__(self, db_path="passwords.db"):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize the database connection and tables"""
        # Create database directory if it doesn't exist
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
            
        create_tables = not os.path.exists(self.db_path)
        
        # Connect to database
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        if create_tables:
            # Create users table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                encryption_salt BLOB NOT NULL
            )
            ''')
            
            # Create passwords table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted BLOB NOT NULL,
                website TEXT,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
            
            self.conn.commit()
    
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None
    
    def add_user(self, username, password):
        """Add a new user with hashed password"""
        # Hash the password
        hashed_password = CryptoManager.hash_password(password)
        
        # Generate salt for encryption
        _, salt = CryptoManager.generate_key_from_password(password)
        
        # Add user to database
        self.cursor.execute(
            'INSERT INTO users (username, password_hash, encryption_salt) VALUES (?, ?, ?)',
            (username, hashed_password, salt)
        )
        self.conn.commit()
        return self.cursor.lastrowid
    
    def authenticate_user(self, username, password):
        """Authenticate a user"""
        self.cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        
        if not result:
            return None
        
        user_id, password_hash = result
        
        if CryptoManager.verify_password(password, password_hash):
            return user_id
        
        return None
    
    def get_encryption_key(self, username, password):
        """Get encryption key for a user"""
        self.cursor.execute('SELECT encryption_salt FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        
        if not result:
            return None
            
        salt = result[0]
        key, _ = CryptoManager.generate_key_from_password(password, salt)
        return key
    
    def add_password(self, user_id, title, username, password, website=None, notes=None, encryption_key=None):
        """Add a new encrypted password entry"""
        if not encryption_key:
            return False
            
        # Encrypt the password
        password_data = password
        encrypted_password = CryptoManager.encrypt_data(password_data, encryption_key)
        
        # Add to database
        self.cursor.execute(
            'INSERT INTO passwords (user_id, title, username, password_encrypted, website, notes) VALUES (?, ?, ?, ?, ?, ?)',
            (user_id, title, username, encrypted_password, website, notes)
        )
        self.conn.commit()
        return True
    
    def get_passwords(self, user_id, encryption_key=None):
        """Get all passwords for a user"""
        if not encryption_key:
            return []
            
        self.cursor.execute(
            'SELECT id, title, username, password_encrypted, website, notes FROM passwords WHERE user_id = ?',
            (user_id,)
        )
        
        results = []
        for row in self.cursor.fetchall():
            id, title, username, password_encrypted, website, notes = row
            
            try:
                decrypted_password = CryptoManager.decrypt_data(password_encrypted, encryption_key)
                results.append({
                    'id': id,
                    'title': title,
                    'username': username,
                    'password': decrypted_password,
                    'website': website,
                    'notes': notes
                })
            except Exception:
                # Skip entries that can't be decrypted
                continue
                
        return results
        
    def update_password(self, password_id, title, username, password, website, notes, encryption_key=None):
        """Update a password entry"""
        if not encryption_key:
            return False
            
        encrypted_password = CryptoManager.encrypt_data(password, encryption_key)
        
        self.cursor.execute(
            'UPDATE passwords SET title = ?, username = ?, password_encrypted = ?, website = ?, notes = ? WHERE id = ?',
            (title, username, encrypted_password, website, notes, password_id)
        )
        self.conn.commit()
        return True
        
    def delete_password(self, password_id):
        """Delete a password entry"""
        self.cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        self.conn.commit()
        return True 