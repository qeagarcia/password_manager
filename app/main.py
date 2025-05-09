import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
from app.utils.database import DatabaseManager
import string
import random

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Initialize database
        self.db = DatabaseManager()
        
        # User state
        self.current_user_id = None
        self.encryption_key = None
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI components"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create frames
        self.login_frame = ttk.Frame(self.notebook)
        self.register_frame = ttk.Frame(self.notebook)
        self.passwords_frame = ttk.Frame(self.notebook)
        
        # Add frames to notebook
        self.notebook.add(self.login_frame, text="Login")
        self.notebook.add(self.register_frame, text="Register")
        
        # Setup login frame
        self.setup_login_frame()
        
        # Setup register frame
        self.setup_register_frame()
        
        # Setup passwords frame (will be added to notebook after login)
        self.setup_passwords_frame()
        
    def setup_login_frame(self):
        """Setup the login page"""
        # Create frame for form
        form_frame = ttk.Frame(self.login_frame, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.login_username = ttk.Entry(form_frame, width=30)
        self.login_username.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.login_password = ttk.Entry(form_frame, width=30, show="*")
        self.login_password.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Login button
        login_btn = ttk.Button(form_frame, text="Login", command=self.login)
        login_btn.grid(row=2, column=1, sticky=tk.W, pady=15)
        
    def setup_register_frame(self):
        """Setup the register page"""
        # Create frame for form
        form_frame = ttk.Frame(self.register_frame, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.register_username = ttk.Entry(form_frame, width=30)
        self.register_username.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.register_password = ttk.Entry(form_frame, width=30, show="*")
        self.register_password.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Confirm Password
        ttk.Label(form_frame, text="Confirm Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.register_password_confirm = ttk.Entry(form_frame, width=30, show="*")
        self.register_password_confirm.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Register button
        register_btn = ttk.Button(form_frame, text="Register", command=self.register)
        register_btn.grid(row=3, column=1, sticky=tk.W, pady=15)
        
    def setup_passwords_frame(self):
        """Setup the passwords management page"""
        # Main frame for the passwords UI
        main_frame = ttk.Frame(self.passwords_frame)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, side=tk.TOP, pady=10)
        
        # Add password button
        add_btn = ttk.Button(button_frame, text="Add Password", command=self.add_password_dialog)
        add_btn.pack(side=tk.LEFT, padx=5)
        
        # Generate password button
        gen_btn = ttk.Button(button_frame, text="Generate Password", command=self.generate_password)
        gen_btn.pack(side=tk.LEFT, padx=5)
        
        # Logout button
        logout_btn = ttk.Button(button_frame, text="Logout", command=self.logout)
        logout_btn.pack(side=tk.RIGHT, padx=5)
        
        # Create treeview for passwords
        self.password_tree = ttk.Treeview(main_frame, columns=("title", "username", "website"), show="headings")
        self.password_tree.heading("title", text="Title")
        self.password_tree.heading("username", text="Username")
        self.password_tree.heading("website", text="Website")
        self.password_tree.column("title", width=150)
        self.password_tree.column("username", width=150)
        self.password_tree.column("website", width=300)
        self.password_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5, pady=5)
        
        # Create scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind double click event
        self.password_tree.bind("<Double-1>", self.show_password_details)
        
    def login(self):
        """Handle login attempt"""
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
            
        # Authenticate user
        user_id = self.db.authenticate_user(username, password)
        if user_id:
            self.current_user_id = user_id
            self.encryption_key = self.db.get_encryption_key(username, password)
            
            # Add passwords tab and select it
            if self.notebook.index("end") == 2:  # If passwords tab isn't added yet
                self.notebook.add(self.passwords_frame, text="Passwords")
            self.notebook.select(2)  # Select passwords tab
            
            # Load passwords
            self.load_passwords()
        else:
            messagebox.showerror("Error", "Invalid username or password")
            
    def register(self):
        """Handle registration attempt"""
        username = self.register_username.get()
        password = self.register_password.get()
        confirm = self.register_password_confirm.get()
        
        if not username or not password or not confirm:
            messagebox.showerror("Error", "Please fill all fields")
            return
            
        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return
            
        try:
            self.db.add_user(username, password)
            messagebox.showinfo("Success", "Account created successfully. Please login.")
            
            # Clear fields and switch to login tab
            self.register_username.delete(0, tk.END)
            self.register_password.delete(0, tk.END)
            self.register_password_confirm.delete(0, tk.END)
            self.notebook.select(0)  # Select login tab
            
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")
            
    def logout(self):
        """Handle logout"""
        self.current_user_id = None
        self.encryption_key = None
        
        # Remove passwords tab
        if self.notebook.index("end") > 2:
            self.notebook.forget(2)
            
        # Clear passwords list
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
            
        # Clear login fields
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        
        # Switch to login tab
        self.notebook.select(0)
        
    def load_passwords(self):
        """Load user passwords into the treeview"""
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
            
        # Get passwords
        passwords = self.db.get_passwords(self.current_user_id, self.encryption_key)
        
        # Add to treeview
        for pw in passwords:
            self.password_tree.insert("", tk.END, values=(pw['title'], pw['username'], pw['website']), iid=pw['id'])
            
    def add_password_dialog(self):
        """Show dialog to add a new password"""
        # Create dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create form
        form_frame = ttk.Frame(dialog, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(form_frame, text="Title:").grid(row=0, column=0, sticky=tk.W, pady=5)
        title_entry = ttk.Entry(form_frame, width=30)
        title_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(form_frame, width=30)
        username_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(form_frame, width=30, show="*")
        password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Website
        ttk.Label(form_frame, text="Website:").grid(row=3, column=0, sticky=tk.W, pady=5)
        website_entry = ttk.Entry(form_frame, width=30)
        website_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=4, column=0, sticky=tk.W, pady=5)
        notes_text = tk.Text(form_frame, width=30, height=5)
        notes_text.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Save button
        def save_password():
            title = title_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            website = website_entry.get()
            notes = notes_text.get("1.0", tk.END).strip()
            
            if not title or not username or not password:
                messagebox.showerror("Error", "Title, username, and password are required", parent=dialog)
                return
                
            success = self.db.add_password(
                self.current_user_id,
                title,
                username,
                password,
                website,
                notes,
                self.encryption_key
            )
            
            if success:
                messagebox.showinfo("Success", "Password saved successfully", parent=dialog)
                dialog.destroy()
                self.load_passwords()
            else:
                messagebox.showerror("Error", "Failed to save password", parent=dialog)
        
        save_btn = ttk.Button(form_frame, text="Save", command=save_password)
        save_btn.grid(row=5, column=1, sticky=tk.E, pady=15)
        
    def show_password_details(self, event):
        """Show dialog with password details when entry is double-clicked"""
        item_id = self.password_tree.selection()[0]
        if not item_id:
            return
            
        # Get password data
        passwords = self.db.get_passwords(self.current_user_id, self.encryption_key)
        password_data = None
        for pw in passwords:
            if str(pw['id']) == str(item_id):
                password_data = pw
                break
                
        if not password_data:
            return
            
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Details")
        dialog.geometry("500x400")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create form
        form_frame = ttk.Frame(dialog, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(form_frame, text="Title:").grid(row=0, column=0, sticky=tk.W, pady=5)
        title_entry = ttk.Entry(form_frame, width=30)
        title_entry.insert(0, password_data['title'])
        title_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(form_frame, width=30)
        username_entry.insert(0, password_data['username'])
        username_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_var = tk.StringVar(value=password_data['password'])
        password_entry = ttk.Entry(form_frame, width=30, show="*", textvariable=password_var)
        password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Toggle password visibility
        show_var = tk.BooleanVar(value=False)
        
        def toggle_password():
            if show_var.get():
                password_entry.config(show="")
            else:
                password_entry.config(show="*")
                
        show_checkbox = ttk.Checkbutton(form_frame, text="Show password", variable=show_var, command=toggle_password)
        show_checkbox.grid(row=2, column=2, sticky=tk.W, pady=5)
        
        # Website
        ttk.Label(form_frame, text="Website:").grid(row=3, column=0, sticky=tk.W, pady=5)
        website_entry = ttk.Entry(form_frame, width=30)
        website_entry.insert(0, password_data['website'] or "")
        website_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=4, column=0, sticky=tk.W, pady=5)
        notes_text = tk.Text(form_frame, width=30, height=5)
        if password_data['notes']:
            notes_text.insert("1.0", password_data['notes'])
        notes_text.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(form_frame)
        buttons_frame.grid(row=5, column=1, sticky=tk.E, pady=15)
        
        # Update button
        def update_password():
            title = title_entry.get()
            username = username_entry.get()
            password = password_var.get()
            website = website_entry.get()
            notes = notes_text.get("1.0", tk.END).strip()
            
            if not title or not username or not password:
                messagebox.showerror("Error", "Title, username, and password are required", parent=dialog)
                return
                
            success = self.db.update_password(
                password_data['id'],
                title,
                username,
                password,
                website,
                notes,
                self.encryption_key
            )
            
            if success:
                messagebox.showinfo("Success", "Password updated successfully", parent=dialog)
                dialog.destroy()
                self.load_passwords()
            else:
                messagebox.showerror("Error", "Failed to update password", parent=dialog)
        
        update_btn = ttk.Button(buttons_frame, text="Update", command=update_password)
        update_btn.pack(side=tk.LEFT, padx=5)
        
        # Delete button
        def delete_password():
            if messagebox.askyesno("Confirm", "Are you sure you want to delete this password?", parent=dialog):
                success = self.db.delete_password(password_data['id'])
                if success:
                    messagebox.showinfo("Success", "Password deleted successfully", parent=dialog)
                    dialog.destroy()
                    self.load_passwords()
                else:
                    messagebox.showerror("Error", "Failed to delete password", parent=dialog)
        
        delete_btn = ttk.Button(buttons_frame, text="Delete", command=delete_password)
        delete_btn.pack(side=tk.LEFT, padx=5)
        
        # Close button
        close_btn = ttk.Button(buttons_frame, text="Close", command=dialog.destroy)
        close_btn.pack(side=tk.LEFT, padx=5)
        
    def generate_password(self):
        """Generate a random secure password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Generator")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create form
        form_frame = ttk.Frame(dialog, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Length
        ttk.Label(form_frame, text="Length:").grid(row=0, column=0, sticky=tk.W, pady=5)
        length_var = tk.IntVar(value=16)
        length_spinbox = ttk.Spinbox(form_frame, from_=8, to=64, textvariable=length_var, width=5)
        length_spinbox.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Character sets
        ttk.Label(form_frame, text="Include:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        options_frame = ttk.Frame(form_frame)
        options_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        uppercase_var = tk.BooleanVar(value=True)
        uppercase_check = ttk.Checkbutton(options_frame, text="Uppercase", variable=uppercase_var)
        uppercase_check.grid(row=0, column=0, sticky=tk.W)
        
        lowercase_var = tk.BooleanVar(value=True)
        lowercase_check = ttk.Checkbutton(options_frame, text="Lowercase", variable=lowercase_var)
        lowercase_check.grid(row=1, column=0, sticky=tk.W)
        
        digits_var = tk.BooleanVar(value=True)
        digits_check = ttk.Checkbutton(options_frame, text="Digits", variable=digits_var)
        digits_check.grid(row=2, column=0, sticky=tk.W)
        
        symbols_var = tk.BooleanVar(value=True)
        symbols_check = ttk.Checkbutton(options_frame, text="Symbols", variable=symbols_var)
        symbols_check.grid(row=3, column=0, sticky=tk.W)
        
        # Password field
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(form_frame, textvariable=password_var, width=30)
        password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Generate function
        def do_generate():
            # Get character sets
            chars = ""
            if uppercase_var.get():
                chars += string.ascii_uppercase
            if lowercase_var.get():
                chars += string.ascii_lowercase
            if digits_var.get():
                chars += string.digits
            if symbols_var.get():
                chars += string.punctuation
                
            if not chars:
                messagebox.showerror("Error", "Please select at least one character set", parent=dialog)
                return
                
            # Generate password
            length = length_var.get()
            password = ''.join(random.choice(chars) for _ in range(length))
            password_var.set(password)
            
        # Copy function
        def copy_password():
            dialog.clipboard_clear()
            dialog.clipboard_append(password_var.get())
            messagebox.showinfo("Success", "Password copied to clipboard", parent=dialog)
            
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=3, column=1, sticky=tk.E, pady=15)
        
        generate_btn = ttk.Button(button_frame, text="Generate", command=do_generate)
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        copy_btn = ttk.Button(button_frame, text="Copy", command=copy_password)
        copy_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(button_frame, text="Close", command=dialog.destroy)
        close_btn.pack(side=tk.LEFT, padx=5)
        
        # Generate initial password
        do_generate()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop() 