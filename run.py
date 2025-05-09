#!/usr/bin/env python
import tkinter as tk
from app.main import PasswordManager

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop() 