import shutil
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
import os
from datetime import datetime
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "aksychdtem1826d8cj2mdxjs8j"

BASE_DRIVE_PATH = os.path.abspath("./Drive")
if not os.path.exists(BASE_DRIVE_PATH):
    os.makedirs(BASE_DRIVE_PATH)

def sha256_hash_string(input_string):
    encoded_string = input_string.encode('utf-8')
    return hashlib.sha256(encoded_string).hexdigest()

@app.route("/")
def start():
    return redirect("/login")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    
    with sqlite3.connect('data.db') as connection:
        cursor = connection.cursor()
        
        username = request.form.get('username')
        password = request.form.get('password')

        cursor.execute("SELECT hash FROM Users WHERE name = ?", (username,))
        result = cursor.fetchone() 

        if result is None:
            return render_template("error.html", code=400, message="Inexistent user")
        
        stored_hash = result[0]
        if stored_hash != sha256_hash_string(password):
            return render_template("error.html", code=401, message="Invalid password")

        if username == "Admin":
            session['is_admin'] = True
            session['user_logged'] = username
            with sqlite3.connect('data.db') as connection:
                cursor = connection.cursor()
                cursor.execute("INSERT INTO logins (user, action, timestamp) VALUES (?, ?, ?)", (session.get("user_logged"), "Login", datetime.now()))
            print(f"Login for {username} at {datetime.now()}")
            return redirect("/admin")

        else:
            session['is_admin'] = False
            session['user_logged'] = username
            with sqlite3.connect('data.db') as connection:
                cursor = connection.cursor()
                cursor.execute("INSERT INTO logins (user, action, timestamp) VALUES (?, ?, ?)", (session.get("user_logged"), "Login", datetime.now()))
            print(f"Login for {username} at {datetime.now()}")
            return redirect("/files")
        
@app.route("/admin", methods=['GET', 'POST'])
def admin():
    if not session.get('is_admin'):
        return render_template('error.html', code=403, message="Unauthorized Access")

    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return render_template("error.html", code=400, message="Passwords do not match!")

        with sqlite3.connect('data.db') as connection:
            cursor = connection.cursor()

            cursor.execute("SELECT name FROM Users WHERE name = ?", (username,))
            if cursor.fetchone():
                return render_template("error.html", code=400, message="User already exists!")

            user_dir = os.path.join(BASE_DRIVE_PATH, username)
            try:
                os.makedirs(user_dir, exist_ok=True)
            except Exception as e:
                return render_template("error.html", code=500, message=f"Failed to create user directory: {e}")

            cursor.execute("INSERT INTO Users (name, hash) VALUES (?, ?)", 
                           (username, sha256_hash_string(password)))
        
        return redirect(url_for('admin'))

    with sqlite3.connect('data.db') as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT name FROM Users")
        users_list = [row[0] for row in cursor.fetchall()]
        
        cursor.execute("SELECT user, action, timestamp FROM logins ORDER BY timestamp DESC LIMIT 20")
        log_data = cursor.fetchall()

    return render_template("admin.html", users=users_list, logs=log_data)

@app.route("/admin/edit/<username>", methods=['GET', 'POST'])
def edit_user(username):
    if not session.get('is_admin'):
        return render_template('error.html', code=403, message="Unauthorized")

    if request.method == 'POST':
        action = request.form.get('action')
        new_name = request.form.get('new_username').strip() if request.form.get('new_username') else None
        new_pass = request.form.get('new_password')

        if username == "Admin":
            return render_template('error.html', code=403, message="The main Admin account cannot be modified here.")

        with sqlite3.connect('data.db') as connection:
            cursor = connection.cursor()
            
            if action == 'update':
                if new_name and new_name != username:
                    cursor.execute("SELECT name FROM Users WHERE name = ?", (new_name,))
                    if cursor.fetchone():
                        return render_template('error.html', code=400, message=f"The username '{new_name}' is already taken.")
                    
                    old_path = os.path.join(BASE_DRIVE_PATH, username)
                    new_path = os.path.join(BASE_DRIVE_PATH, new_name)
                    if os.path.exists(old_path):
                        os.rename(old_path, new_path)

                new_hash = sha256_hash_string(new_pass)
                cursor.execute("UPDATE Users SET name = ?, hash = ? WHERE name = ?", 
                               (new_name or username, new_hash, username))
            
            elif action == 'delete':
                user_dir = os.path.join(BASE_DRIVE_PATH, username)
                if os.path.exists(user_dir):
                    shutil.rmtree(user_dir) 
                cursor.execute("DELETE FROM Users WHERE name = ?", (username,))
        
        return redirect("/admin")

    return render_template("user_edit.html", username=username)
@app.route("/logout")
def logout():
    username = session.get("user_logged")
    with sqlite3.connect('data.db') as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO logins (user, action, timestamp) VALUES (?, ?, ?)", (session.get("user_logged"), "Logout", datetime.now()))
    print(f"Logout for {username} at {datetime.now()}")


    session.clear()
    
    return redirect(url_for('login'))

@app.route('/files', methods=['GET', 'POST'])
@app.route('/files/<path:subpath>', methods=['GET', 'POST'])
def files(subpath=""):
    if not session.get('user_logged'):
        return redirect(url_for('login'))

    user_folder = session.get('user_logged')
    user_root = os.path.join(BASE_DRIVE_PATH, user_folder)
    
    target_path = os.path.normpath(os.path.join(user_root, subpath))

    if not target_path.startswith(user_root):
        return render_template("error.html", code=403, message="Access Denied: You cannot leave your home folder.")

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'upload':
            file = request.files.get('file')
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(target_path, filename))
        
        elif action == 'mkdir':
            new_folder_name = request.form.get('folder_name')
            if new_folder_name:
                new_folder_path = os.path.join(target_path, secure_filename(new_folder_name))
                os.makedirs(new_folder_path, exist_ok=True)
        
        elif action == 'delete':
            item_to_delete = request.form.get('item_name')
            delete_path = os.path.join(target_path, secure_filename(item_to_delete))
            if os.path.exists(delete_path):
                if os.path.isdir(delete_path):
                    shutil.rmtree(delete_path)
                else:
                    os.remove(delete_path)
        
        return redirect(url_for('files', subpath=subpath))

    if os.path.isfile(target_path):
        return send_from_directory(os.path.dirname(target_path), os.path.basename(target_path))

    items = []
    for entry in os.scandir(target_path):
        rel_path = os.path.relpath(entry.path, user_root)
        items.append({
            "name": entry.name,
            "is_dir": entry.is_dir(),
            "rel_path": rel_path.replace("\\", "/")
        })

    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    parent_path = os.path.relpath(os.path.dirname(target_path), user_root)
    
    return render_template('browser.html', 
                           folder_name=subpath if subpath else "Home", 
                           items=items, 
                           show_back=(subpath != "" and subpath != "."), 
                           parent_path="" if parent_path == "." else parent_path)

@app.route('/files/')
def files_bugged():
    return redirect("/files")
            

if __name__ == '__main__':
    app.run(debug=True)
