import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

# ------- CREATE APP -----------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# CREATE SCHEMA IN DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 
# CREATE TABLE IN DB
# with app.app_context():
#     db.create_all()


def setup_logging():
    handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
    # formatter works on the log file, doesn't apply to log prints in console
    formatter = logging.Formatter(
        fmt='[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    # this line doesn't seem to do anything (we have to place logger at app level)
    # handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    print(app.logger.getEffectiveLevel())
    # this line added to the log (otherwise it didn't write)
    # it seems the setLevel might be at DEBUG or ERROR as default
    app.logger.setLevel(logging.INFO)


setup_logging()


# --------- APP ROUTES ----------------
@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    # get from the form (with request.form)
    if request.method == "POST":
        # technically we don't even want variables storing data
        password = request.form.get('password')
        hash_password = generate_password_hash(password,
                                               method='pbkdf2:sha256',
                                               salt_length=8)
        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=hash_password
        )
        print(new_user.name, new_user.email, new_user.password)
        app.logger.info("Attempting to add a new user")
        db.session.add(new_user)
        db.session.commit()
        app.logger.info("User added successfully")
        return render_template("secrets.html", name=request.form.get('name'))

    return render_template("register.html")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    """
    Send/Downloads file when they click on the link with send_...
    """
    directory = "static/files/"
    file_name = "cheat_sheet.pdf"
    return send_from_directory(directory, file_name, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
