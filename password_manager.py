"""
Password Generator and Strength Checker
Tkinter + SQLite student project

Run: python password_manager.py
Python: 3.10+
"""

import secrets
import string
import sqlite3
import re
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

DB_NAME = "password_history.db"


def initialize_database():
    """Create the history table if it does not already exist."""
    with sqlite3.connect(DB_NAME) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                length INTEGER NOT NULL,
                strength TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)


def assess_strength(password):
    """Return a simple strength label and an explanatory message."""
    if not password:
        return "Not entered", "Enter a password to check its strength."

    score = 0
    checks = {
        "At least 8 characters": len(password) >= 8,
        "At least 12 characters": len(password) >= 12,
        "Contains lowercase letters": any(c.islower() for c in password),
        "Contains uppercase letters": any(c.isupper() for c in password),
        "Contains numbers": any(c.isdigit() for c in password),
        "Contains symbols": any(c in string.punctuation for c in password),
    }
    score = sum(checks.values())

    if len(password) < 8:
        label = "Weak"
    elif score <= 3:
        label = "Moderate"
    elif score <= 4:
        label = "Good"
    else:
        label = "Strong"

    missing = [name for name, passed in checks.items() if not passed]
    if not missing:
        message = "Great! The password meets all six basic checks."
    else:
        message = "Improve by adding: " + ", ".join(missing) + "."
    return label, message


def generate_password(length, use_lower, use_upper, use_digits, use_symbols):
    """Generate a random password using selected character groups."""
    groups = []
    if use_lower:
        groups.append(string.ascii_lowercase)
    if use_upper:
        groups.append(string.ascii_uppercase)
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append("!@#$%^&*()-_=+[]{}?")

    if not groups:
        raise ValueError("Select at least one character type.")
    if length < len(groups):
        raise ValueError(
            f"Length must be at least {len(groups)} for the selected character types."
        )

    # Guarantee at least one character from each selected group.
    chars = [secrets.choice(group) for group in groups]
    all_chars = "".join(groups)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator & Strength Checker")
        self.root.geometry("850x680")
        self.root.minsize(760, 620)
        self.root.configure(bg="#f2f5f9")

        self.password_var = tk.StringVar()
        self.length_var = tk.IntVar(value=16)
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready")

        self.build_ui()
        self.refresh_history()

    def build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#f2f5f9")
        style.configure("TLabel", background="#f2f5f9", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 19, "bold"), foreground="#172554")
        style.configure("Subtitle.TLabel", foreground="#475569")
        style.configure("TButton", font=("Segoe UI", 10), padding=7)
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        main = ttk.Frame(self.root, padding=20)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="Password Generator & Strength Checker",
                  style="Title.TLabel").pack(anchor="w")
        ttk.Label(main, text="Create passwords, check strength, and review saved history.",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(3, 15))

        settings = ttk.LabelFrame(main, text="1. Password settings", padding=12)
        settings.pack(fill="x", pady=(0, 12))

        row = ttk.Frame(settings)
        row.pack(fill="x")
        ttk.Label(row, text="Password length:").pack(side="left")
        ttk.Spinbox(row, from_=4, to=64, textvariable=self.length_var,
                    width=6).pack(side="left", padx=(8, 18))
        ttk.Label(row, text="Character types:").pack(side="left", padx=(0, 8))
        ttk.Checkbutton(row, text="Lowercase (a-z)", variable=self.lower_var).pack(side="left", padx=4)
        ttk.Checkbutton(row, text="Uppercase (A-Z)", variable=self.upper_var).pack(side="left", padx=4)
        ttk.Checkbutton(row, text="Numbers (0-9)", variable=self.digits_var).pack(side="left", padx=4)
        ttk.Checkbutton(row, text="Symbols", variable=self.symbols_var).pack(side="left", padx=4)

        actions = ttk.Frame(settings)
        actions.pack(fill="x", pady=(12, 0))
        ttk.Button(actions, text="Generate Password", command=self.on_generate).pack(side="left")
        ttk.Button(actions, text="Check Strength", command=self.on_check).pack(side="left", padx=8)
        ttk.Button(actions, text="Copy Password", command=self.on_copy).pack(side="left")

        result = ttk.LabelFrame(main, text="2. Password result", padding=12)
        result.pack(fill="x", pady=(0, 12))
        self.password_entry = ttk.Entry(result, textvariable=self.password_var,
                                        font=("Consolas", 13), show="*")
        self.password_entry.pack(fill="x", pady=(0, 8))
        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(result, text="Show password", variable=self.show_password_var,
                        command=self.toggle_password).pack(anchor="w")
        self.strength_label = ttk.Label(result, text="Strength: Not checked",
                                        font=("Segoe UI", 11, "bold"))
        self.strength_label.pack(anchor="w", pady=(8, 2))
        self.feedback_label = ttk.Label(result, text="Generate a password or enter one above.",
                                        wraplength=760)
        self.feedback_label.pack(anchor="w")

        history_frame = ttk.LabelFrame(main, text="3. Saved history (SQLite)", padding=10)
        history_frame.pack(fill="both", expand=True)
        columns = ("id", "date", "length", "strength")
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show="headings", height=6)
        self.history_tree.heading("id", text="ID")
        self.history_tree.heading("date", text="Created")
        self.history_tree.heading("length", text="Length")
        self.history_tree.heading("strength", text="Strength")
        self.history_tree.column("id", width=45, anchor="center")
        self.history_tree.column("date", width=230)
        self.history_tree.column("length", width=80, anchor="center")
        self.history_tree.column("strength", width=100, anchor="center")
        scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        self.history_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        bottom = ttk.Frame(main)
        bottom.pack(fill="x", pady=(8, 0))
        ttk.Button(bottom, text="Refresh History", command=self.refresh_history).pack(side="left")
        ttk.Button(bottom, text="Clear History", command=self.clear_history).pack(side="left", padx=8)
        ttk.Label(bottom, textvariable=self.status_var).pack(side="right")

    def toggle_password(self):
        self.password_entry.configure(show="" if self.show_password_var.get() else "*")

    def on_generate(self):
        try:
            length = int(self.length_var.get())
            if not 4 <= length <= 64:
                raise ValueError("Choose a length between 4 and 64.")
            password = generate_password(
                length, self.lower_var.get(), self.upper_var.get(),
                self.digits_var.get(), self.symbols_var.get()
            )
            self.password_var.set(password)
            self.update_strength(password)
            self.save_history(password)
            self.status_var.set("Password generated and saved to history.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid settings", str(error))

    def on_check(self):
        self.update_strength(self.password_var.get())

    def update_strength(self, password):
        strength, feedback = assess_strength(password)
        self.strength_label.configure(text=f"Strength: {strength}")
        self.feedback_label.configure(text=feedback)
        if strength == "Strong":
            self.status_var.set("Strength check complete: Strong")
        elif strength in ("Weak", "Moderate", "Good"):
            self.status_var.set("Strength check complete: " + strength)
        else:
            self.status_var.set("Enter a password first.")

    def on_copy(self):
        password = self.password_var.get()
        if not password:
            messagebox.showinfo("Nothing to copy", "Generate or enter a password first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.status_var.set("Password copied to clipboard.")
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def save_history(self, password):
        strength, _ = assess_strength(password)
        with sqlite3.connect(DB_NAME) as connection:
            connection.execute(
                "INSERT INTO password_history (created_at, length, strength, password) VALUES (?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), len(password), strength, password)
            )
        self.refresh_history()

    def refresh_history(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        with sqlite3.connect(DB_NAME) as connection:
            rows = connection.execute(
                "SELECT id, created_at, length, strength FROM password_history ORDER BY id DESC LIMIT 50"
            ).fetchall()
        for row in rows:
            self.history_tree.insert("", "end", values=row)
        self.status_var.set(f"History loaded: {len(rows)} record(s)")

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Delete all saved password history?"):
            with sqlite3.connect(DB_NAME) as connection:
                connection.execute("DELETE FROM password_history")
            self.refresh_history()
            self.status_var.set("History cleared.")


if __name__ == "__main__":
    initialize_database()
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()
