import mysql.connector
import bcrypt

host = "127.0.0.1"
user = "root"
password = ""
database = "is_project"
port = 3306

connection = None

def initialize_database():
    try:
        # First connect without database
        conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            port=port
        )
        
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS is_project")
        
        # Switch to the database
        cursor.execute("USE is_project")
        
        # Create Users table
        create_users_table = """
        CREATE TABLE IF NOT EXISTS Users (
            username varchar(50) NOT NULL,
            password varchar(255) NOT NULL,
            role varchar(50) NOT NULL,
            PRIMARY KEY (username)
        )
        """
        
        # Create Files table
        create_files_table = """
        CREATE TABLE IF NOT EXISTS Files (
            file_id int NOT NULL AUTO_INCREMENT,
            username varchar(255) DEFAULT NULL,
            iv varbinary(16) DEFAULT NULL,
            encrypted_file mediumblob,
            signature varbinary(512) DEFAULT NULL,
            sender varchar(255) DEFAULT NULL,
            filename varchar(255) DEFAULT NULL,
            upload_time timestamp NULL DEFAULT CURRENT_TIMESTAMP,
            filesize bigint DEFAULT NULL,
            PRIMARY KEY (file_id)
        )
        """
        
        # Create FileIndex table
        create_fileindex_table = """
        CREATE TABLE IF NOT EXISTS FileIndex (
            keyword varchar(64) NOT NULL,
            file_id int NOT NULL,
            PRIMARY KEY (keyword, file_id),
            CONSTRAINT FileIndex_ibfk_1 FOREIGN KEY (file_id) REFERENCES Files (file_id) ON DELETE CASCADE
        )
        """
        
        cursor.execute(create_users_table)
        cursor.execute(create_files_table)
        cursor.execute(create_fileindex_table)
        
        conn.commit()
        print("Database and tables initialized successfully")
        
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def add_user(username, password1, role):
    initialize_database()
    try:
        # Establishing the connection
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            port = port
        )

        if connection.is_connected():
            print("Connected to the database successfully")

            # Creating a cursor object to execute SQL queries
            cursor = connection.cursor()
            
            
            hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
            
            
            insert_query = """
            INSERT INTO Users (username, password, role)
            VALUES (%s, %s, %s)
            """
            cursor.execute(insert_query, (username, hashed_password, role))
            
            connection.commit()
            print("User added successfully")

    except mysql.connector.Error as err:
        print(f"Error: {err}")

add_user("admin", "adminpass", "admin")
# add_user("user1", "pass1", "user")
# add_user("user2", "pass2", "user")