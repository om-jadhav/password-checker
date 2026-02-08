import requests
import hashlib
import re
import argparse
from getpass import getpass
from colorama import Fore, Style, init
init(autoreset=True)

# API requesting
def request_api_data(query_char):   
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')    
    return res   

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def colored(text, color):
    return color + text + Style.RESET_ALL

#Assement of Password Strength
def asses_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score+=1
    else:
        feedback.append("Use at least 8 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else :
        feedback.append("Add an Uppercase letter (A-Z).")

    if re.search(r"[a-z]", password):
        score += 1
    else :
        feedback.append("Add an Lowercase Letter (a-z).")

    if re.search(r"[0-9]", password):
        score += 1
    else :
        feedback.append("Add a number (0-9).")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        score += 1
    else : 
        feedback.append("Add a special Character.")
    
    return score,feedback

#Labelling of Strengtjh of Password
def strength_label(score):
    labels = {
        0: "Very Weak ❌",
        1: "Very Weak ❌",
        2: "Weak ⚠️",
        3: "Medium 🟡",
        4: "Strong 🟢",
        5: "Very Strong 🔥"
    }
    return labels.get(score, "Unknown")
#defining Coloring
def colored_strength(label):
    if "Very Weak" in label or "Weak" in label:
        return colored(label, Fore.RED)
    elif "Medium" in label:
        return colored(label, Fore.YELLOW)
    elif "Strong" in label:
        return colored(label, Fore.GREEN)
    else:
        return label

def main():
    parser = argparse.ArgumentParser(
        description= "🔐 CLI Password Strength & Breach Checker"
    )
    parser.add_argument(
        "--password",
        action="store_true",
        help="Prompt for Password securely (hidden input)"
    )
    
    args = parser.parse_args()

    print("\n🔐 Password Security Analyzer\n")

    #Secure hidden input
    password = getpass("Enter Password (input hidden): ")

    if not password:
        print("❌ No password entered.")
        return
    
    #Strength Check
    score, feedback = asses_password_strength(password)
    label = strength_label(score)

    print("\n📊 Strength Analysis")
    print(f"Strength: {colored_strength(label)} ({score}/5)")

    if feedback:
        print(colored("Suggestions:", Fore.YELLOW))
    for f in feedback:
        print(colored(f" - {f}", Fore.YELLOW))
        
    else:
        print("✅ Password meets all strength requirements.")

    #Breach Check
    count = pwned_api_check(password)

    if count:
        print(colored(f"\n⚠️ Found {count} times in data breaches!", Fore.RED))
        print(colored("❌ Do NOT use this password.", Fore.RED))
    else:
        print(colored("\n✅ Password not found in known breaches.", Fore.GREEN))

    # Secure logging (masked)
    with open("password_check_log.txt", "a", encoding="utf-8") as log_file:
        masked = password[:2] + '*' * (len(password) - 4) + password[-2:]
        log_file.write(
            f"{masked} | Strength: {label} | Breaches: {count}\n"
        )

    print("\n✔ Analysis complete.")

if __name__ == '__main__':
    main()
