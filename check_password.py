import requests
import hashlib

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

def main():
    print("🔐 Pwned Password Checker")
    print("Type 'exit' to quit.\n")

    while True:
        password = input("Enter a password to check: ")

        if password.lower() == 'exit':
            print("Goodbye!")
            break

        count = pwned_api_check(password)
        if count:
            message = f'⚠️ "{password}" was found {count} times! You should probably change your password.'
        else:
            message = f'✅ "{password}" was NOT found. Carry on!'

        print(message)
           # Optional: log to a file with masked password                                           
        with open("password_check_log.txt", "a") as log_file:
            masked = password[:2] + '*' * (len(password) - 4) + password[-2:]
            log_file.write(f'{masked}: {count} times\n')

if __name__ == '__main__':
    main()
