# sparx
SPARX (Spray Passwords on ARX) is a tool designed for password spraying against the Assa Abloy ARX  access control system's administrator interface, aiding in identifying valid  credential combinations through automated authentication attempts.

```
└─$ python3 sparx.py -h

 #####  ######     #    ######  #     #
#     # #     #   # #   #     #  #   #
#       #     #  #   #  #     #   # #
 #####  ######  #     # ######     #
      # #       ####### #   #     # #
#     # #       #     # #    #   #   #
 #####  #       #     # #     # #     #

usage: sparx.py [-h] [-v] (-u USERNAME | -U USER_FILE) (-p PASSWORD | -P PASSWORD_FILE) (-r IP | -R IP_FILE)

SPARX: Password Spraying Tool for Assa Abloy ARX Systems

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output showing all attempts
  -u USERNAME, --username USERNAME
                        Single username for authentication
  -U USER_FILE, --user_file USER_FILE
                        File containing list of usernames for authentication
  -p PASSWORD, --password PASSWORD
                        Single password for authentication
  -P PASSWORD_FILE, --password_file PASSWORD_FILE
                        File containing list of passwords for authentication
  -r IP, --ip IP        Single IP address for the host
  -R IP_FILE, --ip_file IP_FILE
                        File containing list of IP addresses for the hosts

SPARX (Spray Passwords on ARX) is a tool designed for password spraying against the Assa Abloy ARX
access control system's administrator interface, aiding in identifying valid
credential combinations through automated authentication attempts.
```
