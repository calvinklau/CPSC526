'''
CPSC 526 - Fall 2018
Assignment 2 - Question 2
authenticate.py

@author: calvinlau
'''
import sys
import argon2

def accessGranted():
    print "access granted\n"
    sys.exit(0)

def accessDenied():
    print "access denied\n"
    sys.exit(-1)
    
def retrieveAccount(username):
    """
    Fetches the account salt and password hash from the password file using the given username.
    Parses the stored hash until it encounters a newline (i.e., the end of the hash)
    If username doesn't exist in password file, access is denied.
    
    Args:
        username: The username given via cmd line argument
    """
    salt = ""
    pwdHash = ""
    with open("vault", "r") as f:
        acc = f.readline()
        while acc:
            segments = acc.split("::")
            if (segments[0] == username):
                salt = segments[1]
                pwdHash = segments[2]
                remainder = f.readline()
                while remainder != "\n":
                    pwdHash = pwdHash + remainder
                    remainder = f.readline()
                break
            acc = f.readline()
    if salt == "" and pwdHash == "":
        accessDenied()
    else:
        pwdHash = pwdHash.strip()
        return salt, pwdHash
    
def validatePassword(salt, password, pwdHash):
    """
    Uses the stored salt and password hash (from password file) to validate the given password.
    
    Args:
        salt: Retrieved from password file using passed username from cmd line argument
        password: The password given via cmd line argument
        pwdHash: Retrieved from password file using passed username from cmd line argument
    """
    if argon2.argon2_hash(password, salt) == pwdHash:
        accessGranted()
    else:
        accessDenied()
        
if __name__ == '__main__':
    # reject if insufficient cmd line arguments are given
    if len(sys.argv) != 3:
        accessDenied()
        
    inputUser = sys.argv[1]
    inputPass = sys.argv[2]
    
    salt, pwdHash = retrieveAccount(inputUser)
    validatePassword(salt, inputPass, pwdHash)
    