import os
import subprocess
import pickle


# ==========================================
# 1. os.system() with dynamic command
# Expected: python-os-system-command
# ==========================================

filename = input("Enter filename: ")
os.system("cat " + filename)


# ==========================================
# 2. subprocess with shell=True
# Expected: python-subprocess-shell-true
# ==========================================

command = input("Enter command: ")
subprocess.run(command, shell=True)


# ==========================================
# 3. pickle.loads()
# Expected: python-unsafe-pickle-loads
# ==========================================

data = input("Enter serialized data: ")
object_data = pickle.loads(data.encode())


# ==========================================
# 4. pickle.load()
# Expected: python-unsafe-pickle-load
# ==========================================

with open("data.pkl", "rb") as file:
    loaded_data = pickle.load(file)


# ==========================================
# 5. eval()
# Expected: python-dangerous-eval
# ==========================================

expression = input("Enter expression: ")
result = eval(expression)


# ==========================================
# 6. exec()
# Expected: python-dangerous-exec
# ==========================================

code = input("Enter Python code: ")
exec(code)


# ==========================================
# 7. SQL string concatenation
# Expected: python-sql-string-concatenation
# ==========================================

username = input("Username: ")
query = "SELECT * FROM users WHERE username = '" + username + "'"


# ==========================================
# 8. Hardcoded password
# Expected: python-hardcoded-password
# ==========================================

password = "my_secret_password"