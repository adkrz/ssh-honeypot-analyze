import os.path
from collections import defaultdict
import re

username_counts = defaultdict(int)
passwords_counts = defaultdict(int)
unusual_passwords_counts = defaultdict(int)
pairs_counts = defaultdict(int)
specific_user_counts = defaultdict(int)
specific_password_counts = defaultdict(int)

specific_user = "ftpuser"
specific_password = "5nWt3P-fF4WosQm5O"
usual_password_regex = re.compile("^[A-Za-z0-9@!#\$]+$")
total_count = 0

with open(os.path.expanduser("~/ssh-honeypot.log"), "rt", encoding="utf-8") as log:
    for line in log:
        if "started on port" in line or "HASSHServer" in line:
            continue
        idx = line.find("] ")
        if idx == -1:
            continue
        tokens = line[idx + 2:].split(" ")
        username = tokens[1]
        password = " ".join(tokens[2:])  # potential pw with space
        password = password[:-1]  # trailing \n
        pair = username, password
        username_counts[username] += 1
        passwords_counts[password] += 1
        pairs_counts[pair] += 1
        if username == specific_user:
            specific_user_counts[password] += 1
        if password and not re.match(usual_password_regex, password):
            unusual_passwords_counts[password] += 1
        if password == specific_password:
            specific_password_counts[username] += 1
        total_count += 1


def print_top(dic, n):
    last = n - 1
    for i, kvp in enumerate(dic.items()):
        print(kvp)
        if n > 0 and i >= last:
            break


def sort_dict_by_vals(dic):
    return dict(sorted(dic.items(), key=lambda kvp: kvp[1], reverse=True))


username_counts = sort_dict_by_vals(username_counts)
passwords_counts = sort_dict_by_vals(passwords_counts)
pairs_counts = sort_dict_by_vals(pairs_counts)
specific_user_counts = sort_dict_by_vals(specific_user_counts)
unusual_passwords_counts = sort_dict_by_vals(unusual_passwords_counts)
specific_password_counts = sort_dict_by_vals(specific_password_counts)

print(f"Total attempts: {total_count}")
print(f"Unique usernames: {len(username_counts)}")
print(f"Unique passwords: {len(passwords_counts)}")
print(f"Unique user+pass pairs: {len(pairs_counts)}")
print()

print("Top usernames:")
print_top(username_counts, 15)
print()

print("Top passwords:")
print_top(passwords_counts, 50)
print()

print("Top pairs:")
print_top(pairs_counts, 50)
print()

print(f"Top guesses for user {specific_user}")
print_top(specific_user_counts, 15)
print()

print("Unusual passwords")
print_top(unusual_passwords_counts, 50)
print()

print("Longest passwords:")
srt = dict(sorted(passwords_counts.items(), key=lambda kvp: len(kvp[0]), reverse=True))
print_top(srt, 50)
print()

print("Usernames with password " + specific_password)
print_top(specific_password_counts, 50)
print()


#  Rewrite the file to more friendly format for further analysis
with open("pairs.txt", "wt", encoding="utf-8") as pairs:
    for key, value in pairs_counts.items():
        pairs.write(f"{value}\t{key[0]}\t{key[1]}\n")
