import secrets #pip3 install secrets
import string

def password_gen(length):

    characters = string.ascii_letters + string.digits

    generated_pass = ''.join(secrets.choice(characters) for i in range (length))

    return generated_pass

# if __name__ == "__main__":
#     print(password_gen(10))
