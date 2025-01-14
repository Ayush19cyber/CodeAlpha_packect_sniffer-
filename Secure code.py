from flask import Flask, request, render_template, redirect, url_for
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Insecure SQL query susceptible to SQL Injection
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        user = cursor.fetchone()
        
        if user:
            return redirect(url_for('welcome'))
        else:
            return "Invalid credentials"
    
    return render_template('login.html')


@app.route('/welcome')
def welcome():
    return "Welcome to the secured application!"


if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Use a strong, unique key in production

# Database setup
def create_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Secure: Use parameterized queries to prevent SQL injection
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        # Check if user exists and password matches
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['user'] = username  # Set session
            return redirect(url_for('welcome'))
        else:
            return "Invalid credentials"

    return render_template('login.html')


@app.route('/welcome')
def welcome():
    # Ensure user is logged in before displaying welcome page
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return f"Welcome to the secured application, {session['user']}!"


# Route to log out the user
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


# Register a new user (for demo purposes)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Store the user securely with hashed password
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                       (username, hashed_password.decode('utf-8')))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))

    return render_template('register.html')


if __name__ == '__main__':
    create_db()  # Ensure the database is created before running the app
    app.run(debug=False)  # Disable debug mode for production
