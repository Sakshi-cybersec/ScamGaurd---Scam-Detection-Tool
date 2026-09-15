import re
import tkinter as tk
from tkinter import messagebox

# -----------------------------
# Scam detection rules
# -----------------------------

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "right now",
    "today", "within 24 hours", "final warning",
    "account will be blocked", "account will be suspended"
]

SENSITIVE_WORDS = [
    "otp", "password", "pin", "cvv", "verification code",
    "login details", "bank details", "card number"
]

MONEY_WORDS = [
    "pay", "payment", "transfer", "fee", "processing fee",
    "send money", "refund", "prize", "lottery", "won"
]

IMPERSONATION_WORDS = [
    "bank", "police", "government", "income tax",
    "customer care", "support team", "courier",
    "electricity department"
]

SUSPICIOUS_PHRASES = [
    "click the link",
    "verify your account",
    "claim your prize",
    "your account will be blocked",
    "your account will be suspended",
    "send otp",
    "confirm your identity"
]


def analyze_message(message):
    text = message.lower()

    score = 0
    reasons = []

    # Check urgency
    urgency_found = [word for word in URGENCY_WORDS if word in text]
    if urgency_found:
        score += 20
        reasons.append("Urgency or threat language detected")

    # Check sensitive information requests
    sensitive_found = [word for word in SENSITIVE_WORDS if word in text]
    if sensitive_found:
        score += 30
        reasons.append("Request for sensitive information detected")

    # Check money-related language
    money_found = [word for word in MONEY_WORDS if word in text]
    if money_found:
        score += 20
        reasons.append("Money/payment-related language detected")

    # Check impersonation
    impersonation_found = [
        word for word in IMPERSONATION_WORDS if word in text
    ]
    if impersonation_found:
        score += 10
        reasons.append("Possible impersonation detected")

    # Check suspicious phrases
    phrase_found = [
        phrase for phrase in SUSPICIOUS_PHRASES if phrase in text
    ]
    if phrase_found:
        score += 10
        reasons.append("Common social-engineering phrase detected")

    # Check URLs
    urls = re.findall(r'https?://\S+|www\.\S+', text)

    if urls:
        score += 10
        reasons.append("URL detected — verify the destination before opening")

    # Limit score to 100
    score = min(score, 100)

    # Risk classification
    if score >= 70:
        risk = "HIGH RISK"
        recommendation = (
            "Do not click links or provide sensitive information. "
            "Verify the message through an official channel."
        )

    elif score >= 40:
        risk = "MEDIUM RISK"
        recommendation = (
            "Be cautious. Verify the sender and request independently."
        )

    else:
        risk = "LOW RISK"
        recommendation = (
            "No strong scam indicators were detected, "
            "but remain cautious."
        )

    return score, risk, reasons, recommendation


# -----------------------------
# GUI
# -----------------------------

def check_message():
    message = input_box.get("1.0", tk.END).strip()

    if not message:
        messagebox.showwarning(
            "Empty Message",
            "Please enter a message first."
        )
        return

    score, risk, reasons, recommendation = analyze_message(message)

    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        f"RISK LEVEL: {risk}\n"
        f"RISK SCORE: {score}/100\n\n"
    )

    result_box.insert(tk.END, "DETECTED INDICATORS:\n")

    if reasons:
        for reason in reasons:
            result_box.insert(tk.END, f"• {reason}\n")
    else:
        result_box.insert(
            tk.END,
            "• No strong indicators detected\n"
        )

    result_box.insert(
        tk.END,
        f"\nRECOMMENDATION:\n{recommendation}"
    )


# -----------------------------
# Create application window
# -----------------------------

window = tk.Tk()
window.title("ScamGuard - Scam Message Detector")
window.geometry("750x650")

title = tk.Label(
    window,
    text="🛡️ ScamGuard",
    font=("Arial", 24, "bold")
)
title.pack(pady=15)

subtitle = tk.Label(
    window,
    text="AI-Based Social Engineering & Scam Detection Demo",
    font=("Arial", 12)
)
subtitle.pack()

input_label = tk.Label(
    window,
    text="Paste a suspicious message:",
    font=("Arial", 12, "bold")
)
input_label.pack(pady=(20, 5))

input_box = tk.Text(
    window,
    height=8,
    width=80
)
input_box.pack()

check_button = tk.Button(
    window,
    text="🔍 Analyze Message",
    command=check_message,
    font=("Arial", 12, "bold"),
    padx=20,
    pady=10
)
check_button.pack(pady=15)

result_label = tk.Label(
    window,
    text="Analysis Result",
    font=("Arial", 14, "bold")
)
result_label.pack()

result_box = tk.Text(
    window,
    height=14,
    width=80
)
result_box.pack(pady=10)

window.mainloop()