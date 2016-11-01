CREATE TABLE users(
user_id TEXT PRIMARY KEY NOT NULL,
user_name TEXT NOT NULL,
password_hash TEXT NOT NULL,
is_admin BOOLEAN NOT NULL);

CREATE TABLE files_annotated_by_users(
user_id TEXT PRIMARY KEY NOT NULL,
user_name TEXT NOT NULL,
file_name TEXT NOT NULL);
