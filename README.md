# Flask-local-server
A simple home file server with multi-user support made with flask.

To use, just download it and run with python flask.
The default user is "Admin" (with capital A), and it's password is password123; when logging in as Admin, you can check
the logs and add/delete users, and to change admin's password, just generate a new sha256 hash for the password you
want and replace the original hash in the "users" table in data.db sqlite3 database (the hasher are not salted).

#Install guide
Download with "git clone https://www.github.com/rauljgmesquita/Flask-local-server" on terminal
Go to the directory where you downloaded and run "cd  Flask-local-server/Pi\ server" on the terminal
Install the dependencies in requirements.txt with pip
Then, with python 3.13, flask and the other dependencies installed, execute "flask run --host=0.0.0.0" on the terminal
Now you can access the server by entering the second ip adress showed on servers screen on the browser of any device
connected to the same wifi or network as the server.
