# ssh-honeypot-analyze
The Python script + analysis results from running SSH honeypot on one of my servers.
The script analyzes log file produced by: https://github.com/droberson/ssh-honeypot. It is a very simple file scanner that collects simple statistics about usernames and passwords. Adjust the content to your needs.

## General conclusions after running honeypot:
- change the default port of SSH from 22 to something else, preferrably above 20k. Note: ports like 222, 2222 are scanned by bots as well, be creative. After changing the port, most of the automated attacks was filtered out.
- disallow root login - most of password attempts was for root
- disallow login with empty password - this should be default configuration of sshd anyway. Amount of trials with empty password is surprising.
- use some good password, 123456 is not a good one :)
- do not use password == username
- install fail2ban. If you changed the default SSH port, remember to change the number in fail2ban config as well.
