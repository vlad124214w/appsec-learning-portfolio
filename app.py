import sqlite3

def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    conn = sqlite3.connect('db.sqlite')
    conn.execute(query)

get_user("test")