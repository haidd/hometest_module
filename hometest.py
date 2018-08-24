# Copyright 2018 haidd
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from passlib.context import CryptContext
from string import ascii_uppercase, ascii_lowercase, digits


def contains(required_chars, s):
    return any(c in required_chars for c in s)


def contains_upper(s):
    return contains(ascii_uppercase, s)


def contains_lower(s):
    return contains(ascii_lowercase, s)


def contains_digit(s):
    return contains(digits, s)


def contains_special(s):
    return contains(r"""!@$%^&*()_-+={}[]|\,.></?~`"':;""", s)


def not_contains_whitespace(s):
    return not contains(' ', s)


def long_enough(s):
    return len(s) >= 6


def validate_password(password):
    # Based on https://codereview.stackexchange.com/questions/165187/password-checker-in-python
    VALIDATIONS = (
        (contains_upper, '- Password needs at least one upper-case character.\n'),
        (contains_lower, '- Password needs at least one lower-case character.\n'),
        (contains_digit, '- Password needs at least one number.'),
        (contains_special, '- Password needs at least one special character.\n'),
        (not_contains_whitespace, '- Password must not contain any whitespace.\n'),
        (long_enough, '- Password needs to be at least 6 characters in length.\n'),
    )
    failures = [
        msg for validator, msg in VALIDATIONS if not validator(password)
    ]
    if not failures:
        return True
    else:
        print("\nInvalid password! Review below and change your password accordingly!\n")
        for msg in failures:
            print(msg)
        print('')
        return False


crypt_context = CryptContext(
    # kdf which can be verified by the context. The default encryption kdf is
    # the first of the list
    ['pbkdf2_sha512', 'md5_crypt'],
    # deprecated algorithms are still verified as usual, but ``needs_update``
    # will indicate that the stored hash should be replaced by a more recent
    # algorithm. Passlib 1.6 supports an `auto` value which deprecates any
    # algorithm but the default, but Ubuntu LTS only provides 1.5 so far.
    deprecated=['md5_crypt'],
)

filename = 'password.txt'


class PasswordManager:
    def __init__(self, user_name, password_encrypted=''):
        self.user_name = user_name
        self.password_encrypted = password_encrypted

    def set_password(self, password):
        '''
        Encrypts then stores the provided plaintext password for the user
        '''
        self.password_encrypted = crypt_context.encrypt(password)
        out_file = open(filename, "wt")
        out_file.write(self.user_name + "," + self.password_encrypted + "\n")
        out_file.close()
        return True

    def verify_password(self, user_name, password):
        in_file = open(filename, "rt")
        while True:
            in_line = in_file.readline()
            if not in_line:
                return True
            in_line = in_line[:-1]
            user_name_stored, password_encrypted_stored = in_line.split(",")
            if user_name == user_name_stored:
                valid_pass, replacement = crypt_context.verify_and_update(
                    password,
                    password_encrypted_stored
                )
                in_file.close()
                if not valid_pass:
                    return False
                return True


if __name__ == '__main__':
    print('\n=============================================')
    print('Welcome to Password Manager!')
    print('=============================================\n')
    while True:
        print('[1] Create new user\n')
        print('[2] Validate your password\n')
        print('[3] Login\n')
        print('[4] Change password\n')
        print('[5] Exit\n')
        choice = int(input("Choose your choice: "))
        print()
        if choice == 1:
            print('------------------ Create new user -----------------\n')
            user_name = input("Enter user name: ")
            # Create new user
            new_user = PasswordManager(user_name)
            valid_password = False
            while valid_password is False:
                password = input("Enter password: ")
                valid_password = validate_password(password)
                continue
            # Encrypt
            new_user.set_password(password)
            print("\n>>> Password meets all requirements and may be used.\n")
            print('-----------------------------------\n')
            continue

        elif choice == 2:
            print('---------------- Validate your password ----------------\n')
            valid_password = False
            while valid_password is False:
                password = input("Enter example password: ")
                valid_password = validate_password(password)
                continue
            print(">>> Password meets all requirements and may be used.\n")
            print('-----------------------------------\n')
        elif choice == 3:
            print('---------------- Login ----------------\n')
            user_name = input("Enter user name: ")
            valid_password = False
            while valid_password is False:
                password = input("Enter password: ")
                user = PasswordManager(user_name, password)
                valid_password = user.verify_password(user_name, password)
                if not valid_password:
                    print(">>> Please try again.\n")
                    continue
                print(">>> Login successfully.\n")
                continue
            print('-----------------------------------\n')
        elif choice == 4:
            print('---------------- Change password ----------------\n')
            user_name = input("Enter user name: ")
            new_valid_password = False
            while new_valid_password is False:
                new_password = input("Enter new password: ")
                new_valid_password = validate_password(new_password)
                continue
            user = PasswordManager(user_name)
            user.set_password(new_password)
            print(">>> Change password successfully.\n")
            print('-----------------------------------\n')
        elif choice == 5:
            print('Thank for using!!!   ')
            break
        else:
            print('Are you kidding me ??? Please try again\n')
            print('-----------------------------------\n')
            continue
