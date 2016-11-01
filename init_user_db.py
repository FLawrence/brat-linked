from sys import argv,exit
from uuid import uuid1
from hashlib import sha256
from os.path import isfile
from sqlite3 import connect

user_db = argv[1]
user_name = argv[2]
password = argv[3]

# Generate a UUID for the user and hash his/her password so it's not just in plain text.
user_id = uuid1().hex
hashed_password = sha256(password).hexdigest()

# The person running this will have BRAT admin privileges, but it might not be ideal to set it this 
# way--who'll have access to this script?
is_admin = True

if not isfile(user_db):
	# User database isn't there. Print an error message and bail out. 
	# print("User database does not exist; exiting")
	exit("User database does not exist; exiting")
	
try:
	conn = connect(user_db)
	curs = conn.cursor()
	curs.execute("INSERT INTO users VALUES (?,?,?,?)", (user_id,user_name,hashed_password,is_admin))
	conn.commit()
	conn.close()
except Exception as e:
	# Quick and dirty generic exception catch...
	print("Database error: " + str(e))
	