# About the Project
Share Up is a file sharing website built using Flask (Python). Database used is MySQL. Frontend is made using simple HTML, CSS and JS.
The project implements multiple aspects of information security.
- Files are encrypted using AES-128 and then stored on the database server.
- Files are hashed and signed (Schnorr Digital Signature) for data integrity and to ensure that the files com from the right party.
- User Passwords are salted and hashed (SHA-256).

# Screenshots

![Client_Dashboard](https://github.com/siddharth108s/ShareUp/blob/master/Client_Dashboard.png?raw=true)

![Admin_Dashboard](https://github.com/siddharth108s/ShareUp/blob/master/Client_Dashboard.png?raw=true)

# Usage
- Use Python 3.10.11. Creating a virtual environment in recommended.
- Install and start MySQL server or use a remote server. Update the credentials in dbconnect.py and app.py files accordingly.
```bash
pip install flask
pip install pycryptodome
pip install mysql-connector-python

python dbconnect.py
python app.py 
```
