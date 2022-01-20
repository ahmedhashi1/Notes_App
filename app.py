from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user 
from flask_login import LoginManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = "my super secret key"

db = SQLAlchemy(app)


class User(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	email = db.Column(db.String(80), unique=True, nullable=False)
	first_name = db.Column(db.String(80), unique=True, nullable=False)
	password = db.Column(db.String(80), unique=True, nullable=False)
	date = db.Column(db.DateTime, default=datetime.utcnow)
	notes= db.relationship('Note')
 
	def __repr__(self):
		return '<First_name %r>' % self.first_name


class Note(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	data = db.Column(db.String(80), unique=True, nullable=False)
	date = db.Column(db.DateTime, default=datetime.utcnow)
	user_id=db.Column(db.Integer, db.ForeignKey('user.id'))
	
@app.route('/login', methods=['GET','POST'])

def login():
	title='Login'
	if request.method=="POST":
		email = request.form.get('email')
		password = request.form.get('password')
		user=User.query.filter_by(email=email).first()
		if user:
			if check_password_hash(user.password,password):
				flash('Logged in sucessfully!', category='success')
				login_user(user, remember=True)
				return redirect(url_for('home.html'))
			else:
				flash('Incorrect password, try again', category='error')
		else:
			flash('Email does not exist', category='error')


	return render_template('login.html',title=title)


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('auth.login'))

@app.route('/signup', methods=['GET','POST'])
def signup():
	title='Sign up'
	if request.method=="POST":
		email=request.form.get('email')
		first_name=request.form.get('first_name')
		password=request.form.get('password')
		confirm_password=request.form.get('confirm_password')

		user=User.query.filter_by(email=email).first()
		if user:
			flash('Email already exists', category='error')
		elif len(email)<4:
			flash('Email must be greater than 3',category='error')
		elif len(first_name)<3:

			flash('Name must be greater than 2',category='error')
		elif len(password)<7:
			flash('Password must be greater than 6...',category='error')
		elif password != confirm_password:
			flash('Password does not match',category='error')	
		else:
			new_user=User(email=email,first_name=first_name,password=generate_password_hash(password,method='sha256'))
			db.session.add(new_user)
			db.session.commit()
			flash('Account created',category='success')
			login_user(user, remember=True)
			return redirect(url_for('home'))


	return render_template('signup.html',title='title')


@app.route('/')
@login_required
def home():
	title='Home'
	return render_template('home.html',title=title)



