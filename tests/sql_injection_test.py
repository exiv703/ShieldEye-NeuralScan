#!/usr/bin/env python3
"""
Test file with SQL Injection vulnerabilities
This file contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""

import sqlite3
import mysql.connector

class UserDatabase:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
    
    def get_user_by_id(self, user_id):
        # VULNERABILITY: SQL Injection - direct string concatenation
        query = "SELECT * FROM users WHERE id = " + user_id
        self.cursor.execute(query)
        return self.cursor.fetchone()
    
    def authenticate_user(self, username, password):
        # VULNERABILITY: SQL Injection - string formatting
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
        self.cursor.execute(query)
        return self.cursor.fetchone()
    
    def search_users(self, search_term):
        # VULNERABILITY: SQL Injection - f-string interpolation
        query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
        self.cursor.execute(query)
        return self.cursor.fetchall()
    
    def delete_user(self, user_id):
        # VULNERABILITY: SQL Injection - .format() method
        query = "DELETE FROM users WHERE id = {}".format(user_id)
        self.cursor.execute(query)
        self.conn.commit()
    
    def update_email(self, user_id, new_email):
        # VULNERABILITY: SQL Injection - multiple concatenations
        query = "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)
        self.cursor.execute(query)
        self.conn.commit()

class MySQLDatabase:
    def __init__(self, host, user, password, database):
        self.conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        self.cursor = self.conn.cursor()
    
    def get_orders(self, customer_id):
        # VULNERABILITY: SQL Injection in MySQL
        sql = "SELECT * FROM orders WHERE customer_id = " + customer_id
        self.cursor.execute(sql)
        return self.cursor.fetchall()
    
    def admin_login(self, username, password):
        # VULNERABILITY: SQL Injection with OR 1=1 possibility
        query = f"SELECT * FROM admins WHERE username='{username}' AND password='{password}'"
        self.cursor.execute(query)
        return self.cursor.fetchone() is not None
