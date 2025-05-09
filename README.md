# Secure Password Manager

A simple offline password manager that uses two different encryption algorithms to secure your passwords:
- Bcrypt for master password hashing
- Fernet symmetric encryption (AES-128) for encrypting stored passwords

## Features

- User authentication with secure password hashing
- Encrypted storage of passwords in a local SQLite database
- Password generator with customizable options
- Modern GUI built with Tkinter
- Ability to create, view, update, and delete password entries

## Security Features

1. **Master Password Hashing**: Uses bcrypt, a slow and computationally expensive algorithm designed to resist brute-force attacks
2. **Password Encryption**: Uses Fernet symmetric encryption, which is built on AES in CBC mode with PKCS7 padding
3. **Key Derivation**: Utilizes PBKDF2 with SHA-256 to derive encryption keys from the master password
4. **Offline Storage**: All data is stored locally in an encrypted SQLite database

## Requirements

- Python 3.6+
- Tkinter (usually included with Python)
- SQLite3 (usually included with Python)
- bcrypt
- cryptography

## Installation

1. Clone this repository
2. Install required packages:

```
pip install -r requirements.txt
```

## Usage

Run the application:

```
python -m app.main
```

1. Register a new account with a secure master password
2. Log in to access your passwords
3. Add, view, update, or delete password entries as needed

## Security Notes

- Your master password is never stored directly
- All sensitive data is encrypted before being written to disk
- The application is offline-only for enhanced security 