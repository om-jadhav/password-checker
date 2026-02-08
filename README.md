# 🔐 Password Security & Complexity Checker (CLI Tool)

A Python-based **Command Line Interface (CLI)** tool that evaluates password strength and checks whether a password has been exposed in known data breaches using the **Have I Been Pwned (HIBP) Passwords API**.  
The tool follows security best practices by **hiding password input**, using **k-anonymity**, and providing **clear, actionable feedback**.

---

## 🚀 Features

- ✅ Secure password input (hidden while typing)
- 📊 Password strength assessment based on:
  - Length
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters
- 🎨 Colored CLI output for better readability
- 🔍 Breach detection using Have I Been Pwned API
- 🛡 Uses k-Anonymity (only first 5 hash characters sent)
- 📝 Secure logging with masked passwords
- 💻 Cross-platform (Windows, Linux, macOS)

---

## 🧠 Password Strength Criteria

| Criteria | Requirement |
|--------|-------------|
| Length | ≥ 8 characters |
| Uppercase | At least one (A–Z) |
| Lowercase | At least one (a–z) |
| Number | At least one (0–9) |
| Special Character | Any non-alphanumeric symbol (`_ @ # !` etc.) |

### Strength Levels
- **Very Weak ❌**
- **Weak ⚠️**
- **Medium 🟡**
- **Strong 🟢**
- **Very Strong 🔥**

---

## 🛠 Technologies Used

- **Python 3**
- `requests` – API communication
- `hashlib` – SHA-1 hashing
- `re` – regex-based validation
- `argparse` – CLI argument handling
- `getpass` – hidden password input
- `colorama` – colored terminal output

---

## 📦 Installation

### 1️⃣ Clone the repository
git clone https://github.com/your-username/password-checker.git
cd password-security-checker

### 2️⃣ Install dependencies
pip install requests colorama

## ▶️ Usage

Run the tool from the terminal:
```bash
python check_password.py


You will be prompted to enter a password securely (input will be hidden).

🧪 Sample Output
🔐 Password Security Analyzer

📊 Strength Analysis
Strength: Strong 🟢 (4/5)

Suggestions:
 - Add a special character

✅ Password not found in known breaches.
```
## 🔐 Security & Privacy

- Passwords are never sent in plain text

- Only the first 5 characters of the SHA-1 hash are sent to the API

- Full password hash never leaves the local machine

- Logged passwords are masked, not stored in plain text

## 📝 Logging Format

Example log entry:

pa****rd | Strength: Strong | Breaches: 0


Log file uses UTF-8 encoding to safely support Unicode characters.

## 📚 Learning Outcomes

- Implemented secure password handling in CLI applications

- Used real-world cybersecurity APIs

- Applied regex for password policy enforcement

- Handled Unicode encoding issues on Windows

- Improved CLI UX with colors and structured output

## 🔮 Future Enhancements

- --strength-only or --breach-only flags

- Password strength meter bar

- Export results to CSV/JSON

- GUI or Web version (Flask)

- Configurable password policies

## 👨‍💻 Author

Om Jadhav
Computer Engineering Student | Cybersecurity Enthusiast
Feel free to connect and contribute!

## ⭐ If you find this useful

Give the repository a ⭐ and feel free to fork or improve it!
