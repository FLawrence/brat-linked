CREATE TABLE users(
user_id TEXT PRIMARY KEY NOT NULL,
user_name TEXT NOT NULL UNIQUE,
password_hash TEXT NOT NULL,
is_admin BOOLEAN NOT NULL);

/* Might end up dropping this table in favor of an overall annotations one. 
For now, it's not used. */
CREATE TABLE files_annotated_by_users(
user_id TEXT PRIMARY KEY NOT NULL,
user_name TEXT NOT NULL,
file_name TEXT NOT NULL);

CREATE TABLE groups(
group_id INTEGER PRIMARY KEY,
group_name TEXT NOT NULL UNIQUE)

/* User/group name combinations are set as unique so we don't get duplicates. 
It's possible to either throw an error or silently replace 
the combination if a duplicate occurs...which is better? */
CREATE TABLE group_memberships(
membership_id INTEGER PRIMARY KEY,
user_name TEXT NOT NULL,
group_name TEXT NOT NULL,
UNIQUE (user_name, group_name)
)

/* Set as directory-level permissions for now, because that's what BRAT
seems to expect, and it looks like it would be an absolute bear to change. 
We can try changing to document-level permissions later, though.
Defaulting to group-level permissions for now because this will be used in classes, and 
group-level permissions makes the most sense. 

As with group memberships, we're setting the permission relationships as unique to avoid duplicates.

There's no "can read" column because the existence of a record implies read
permissions, and the absence of one implies no permissions. There's a 
column for indicating write permissions, although getting that to work will 
be tricky; off-the-shelf BRAT assumes that if you can read it, you can write to it. 

NB: SQLite has no built-in boolean type; 0 is false, 1 is true. Untidy. Need to account for that
in the code. */
CREATE TABLE doc_permissions(
permission_id INTEGER PRIMARY KEY,
doc_path TEXT NOT NULL UNIQUE,
group_name TEXT NOT NULL,
can_write BOOLEAN NOT NULL,
UNIQUE(doc_path, group_name)
)
