from flask import Flask, render_template, request, url_for, redirect, flash, send_file, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'blabbermouths'

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'users.db')}"
db = SQLAlchemy()
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

@property
def is_active(self):
    return True

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']

        hashed_pass = generate_password_hash(password, method='scrypt', salt_length=8)

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        if user:
            flash("You've already signed up with that email, login in instead")
            return render_template('login.html')


        new_user = User(name=username, email=email, password=hashed_pass)
        db.session.add(new_user)
        db.session.commit()
        db.session.close()
        return render_template('secrets.html', name=username)
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()


        if user and check_password_hash(user.password, password):
            login_user(user)
            #return redirect(url_for('secrets'))
            return render_template('secrets.html', name=current_user.name)
        elif user:
            flash('Password incorrect, please try again.')
        else:
            flash('That email does not exist, please try again')

    return render_template('login.html')

@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    #return send_file('static/files/cheat_sheet.pdf', as_attachment=True)   #Correct way but it just redirects to download
    return send_from_directory('static', 'files/cheat_sheet.pdf') # On the other hand it redirects to show pdf


if __name__ == "__main__":
    app.run(debug=True)
