'''
CPSC 526 - Fall 2018
Assignment 2 - Question 2
enroll.py

@author: calvinlau
'''
import sys
import uuid
import argon2

def checkUserExists(username):
    """
    Checks the password file to see if the given username exists.
    If the username exists, input is rejected.
    
    Args:
        username: The username given via cmd line argument
    """
    with open("vault") as f:
        vault = f.readlines()
        vault = [x.strip() for x in vault]
    for account in vault:
        user = account.split("::")
        if (user[0] == username):
            reject()
    
def validatePassword(password):
    """
    Validates that the given password is not simple.
    If <password>.isdigit() is true, it is rejected.
    For each word in the words file, if either side of the word is simply numbers, it is rejected.
    Args:
        password: The password given via cmd line argument
    """
    if password.isdigit():
        reject()
    with open("words") as f:
        words = f.readlines()
        words = [x.strip().strip("\\") for x in words]
    for word in words:
            segments = password.split(word, 1)
            if (segments[0].isdigit() or segments[0] == '') and (segments[1].isdigit() or segments[1] == ''):
                reject()
                
def reject():
    print "rejected\n"
    sys.exit(-1)

def accept(user, salt, pwdHash):
    """
    Uses the given username, produced salt, and corresponding password hash
    to write to the password file.
    
    Args:
        user: The username given via cmd line argument
        salt: Generated using uuid library
        pwdHash: Hash of password from cmd line argument using Argon2 and salt
    """
    print pwdHash
    with open("vault", "a") as f:
#         f.write("{0}::{1}::{2}\n".format(user, salt, pwdHash))
        f.write("{0}::{1}::{2}\n\n".format(user, salt, pwdHash))
    print "accepted\n"
    sys.exit(0)

if __name__ == '__main__':
    # reject if insufficient cmd line arguments are given
    if len(sys.argv) != 3:
        reject()
        
    inputUser = sys.argv[1]
    inputPass = sys.argv[2]
    
    checkUserExists(inputUser)
    
    validatePassword(inputPass)
    
    # generate hash using uuid library
    salt = uuid.uuid4().hex
    """
    Argon2 hashing function.
    Default hash parameters:
        inputPass = user-given password
        salt = generated salt
        t: time cost = 16
        m: memory cost = 8
    """
    accept(inputUser, salt, argon2.argon2_hash(inputPass, salt))
    