import tkinter as tk
from tkinter import ttk
import re

def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (min 8 characters).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Include a number.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Include a special character.")

    common_passwords = ["123456", "password", "qwerty", "abc123"]
    if password.lower() in common_passwords:
        feedback.append("Very common password.")
        score = 0

    if score == 5:
        verdict = "✅ Strong password!"
        color = "green"
    elif score >= 3:
        verdict = "⚠️ Medium strength password."
        color = "orange"
    else:
        verdict = "❌ Weak password."
        color = "red"

    return verdict, feedback, score, color

def update_feedback(event=None):
    password = entry.get()
    verdict, feedback, score, color = check_password_strength(password)
    result_label.config(text=verdict, fg=color)
    feedback_text.delete("1.0", tk.END)
    for f in feedback:
        feedback_text.insert(tk.END, f + "\n")
    strength_bar["value"] = score * 20

def toggle_password():
    if entry.cget("show") == "":
        entry.config(show="*")
        toggle_btn.config(text="Show")
    else:
        entry.config(show="")
        toggle_btn.config(text="Hide")

# GUI setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("450x400")
root.configure(bg="#f0f0f0")
root.resizable(False, False)

tk.Label(root, text="Enter your password:", font=("Arial", 12), bg="#f0f0f0").pack(pady=10)
entry_frame = tk.Frame(root, bg="#f0f0f0")
entry_frame.pack()

entry = tk.Entry(entry_frame, show="*", width=30, font=("Arial", 12))
entry.pack(side=tk.LEFT, padx=5)
entry.bind("<KeyRelease>", update_feedback)

toggle_btn = tk.Button(entry_frame, text="Show", command=toggle_password, font=("Arial", 10))
toggle_btn.pack(side=tk.LEFT)

result_label = tk.Label(root, text="", font=("Arial", 14, "bold"), bg="#f0f0f0")
result_label.pack(pady=10)

strength_bar = ttk.Progressbar(root, length=300, mode="determinate", maximum=100)
strength_bar.pack(pady=5)

feedback_text = tk.Text(root, height=6, width=50, font=("Arial", 10))
feedback_text.pack(pady=10)

root.mainloop()
