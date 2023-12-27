import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from sqlalchemy import Result
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

# ------- CREATE APP -----------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# ------------ CONNECT DB WITH APP ------------------
db = SQLAlchemy()
db.init_app(app)

# ----------- CONNECT LOGIN MANAGER TO APP -----------------
# 1) connects your application with the flask-login library
login_manager = LoginManager()
login_manager.init_app(app)


# -------------- DB OPERATIONS ----------------
# CREATE SCHEMA IN DB AND AUTHENTICATE
# https://flask-login.readthedocs.io/en/latest/#your-user-class
# inheriting UserMixin class, automatically provides the necessary properties and methods
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# ----------- CREATE TABLE IN DB ---------------
with app.app_context():
    db.create_all()


# ------------- AUTHENTICATION ------------------
# https://flask.palletsprojects.com/en/latest/quickstart/#sessions
# session - stores information specific to the user (flask objects = request, session)
app.secret_key = b'_5#y2T"RF33z\n\xec]/'


# 2) create a user_loader callback function
@login_manager.user_loader
def load_user(user_id: str):
    """
    User Loader callback function (decorated function).
    The login_manager.user_loader() function will wrap functionality
    on top of the callback function that we decide to define (load_user)
    """
    return db.get_or_404(User, user_id)


# --------------- LOGGING -----------------
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

        # log in and authenticate user after adding details to database
        login_user(new_user)

        return render_template("secrets.html", name=request.form.get('name'))

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    """
    Here we use a class to represent and validate our client-side form data.
    For example, WTForms is a library that will handle this for us, and we use
    a custom LoginForm to validate.
    """
    if request.method == "POST":
        email: str = request.form.get("email")
        password: str = request.form.get("password")
        result: Result = db.session.execute(db.select(User)
                                            .where(User.email == email))
        user: User = result.scalar()

        # check stored password hash against entered password hashed
        if check_password_hash(user.password, password):
            login_user(user)
            return render_template("secrets.html")

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    """
    @login_required - requires the user to be logged in, to access
    the secrets() function
    """
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download')
@login_required
def download():
    """
    Send/Downloads file when they click on the link with send_...
    """
    directory = "static/files/"
    file_name = "cheat_sheet.pdf"
    return send_from_directory(directory, file_name, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
