import requests
import hashlib
import re 
class password_strength_checker:
    
    def __init__(self, password: str):
        self.password = password


    def check_stenghth(self):
        length_error = len(self.password) < 8
        uppercase_error = re.search(r"[A-Z]", self.password) is None  
        lowercase_error = re.search(r"[a-z]", self.password) is None
        digit_error = re.search(r"\d", self.password) is None
        special_char_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", self.password) is None

        self.password_ok = not ( length_error or uppercase_error or lowercase_error or digit_error or special_char_error)

        if not self.password_ok:
            print(f"Password is weak. Please ensure it has at least 8 characters, including uppercase letters, lowercase letters, digits, and special characters.\n Length error: {length_error}, \n Uppercase error: {uppercase_error}, \n Lowercase error: {lowercase_error}, \n Digit error: {digit_error}, \n Special character error: {special_char_error}")

        return  
    
    def check_breach(self):
        #hashing the password using sha1
        sha1_password = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        first5_char, tail = sha1_password[:5], sha1_password[5:]

        #using the have i been pwned API to check for breached passwords
        response = requests.get('https://api.pwnedpasswords.com/range/' + first5_char)
        if response.status_code != 200:
            raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again')
        
        #checking the matched hashes from the response of breached database and returning the results
        for line in response.text.splitlines():
                     hash, count = line.split(':')
                     if hash == tail:
                         if self.password_ok:
                            print(f'The password {self.password} is Good. But it was found {count} times in BREACHED DATABSE ... you should probably change your password!')
                         result = True

        if not result:
            print(f'The password {self.password} was NOT found in BREACHED DATABSE. Carry on!')
            result = False




def main():
     
    print("Enter the password to be checked:")
    password = input()
    checker = password_strength_checker(password)      
    checker.check_stenghth()
    checker.check_breach()


if __name__ == "__main__":
         main()
    
