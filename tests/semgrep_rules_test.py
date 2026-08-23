import os
import subprocess
import pickle
import json


# ==========================================
# SHOULD BE DETECTED
# ==========================================

# 1. os.system - command injection risk
filename = input("Filename: ")
os.system("cat " + filename)


# 2. subprocess with shell=True
command = input("Command: ")
subprocess.run(command, shell=True)


# 3. pickle.loads
data = input("Serialized data: ")
obj = pickle.loads(data.encode())


# 4. pickle.load
with open("data.pkl", "rb") as file:
    obj = pickle.load(file)


# 5. eval
expression = input("Expression: ")
result = eval(expression)


# 6. exec
code = input("Code: ")
exec(code)


# 7. SQL query construction
username = input("Username: ")
query = "SELECT * FROM users WHERE username = '" + username + "'"


# 8. Hardcoded secret
password = "my_secret_password"


# ==========================================
# SHOULD NOT BE DETECTED
# ==========================================

# Safe file reading
with open("important.txt", "r") as file:
    content = file.read()


# Safe subprocess usage
subprocess.run(["cat", "important.txt"], shell=False)


# Safe JSON deserialization
json_data = '{"name": "Ayush"}'
obj = json.loads(json_data)


# Normal arithmetic
number = 10
result = 100 / number


# Normal loop
count = 0
while count < 10:
    print(count)
    count += 1


# Normal function
def greet(name):
    return f"Hello, {name}"


print(greet("World"))