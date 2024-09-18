from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from flask_mail import Mail, Message
from flask import render_template, url_for
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_login import current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.your-email-provider.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
	os.makedirs(app.config['UPLOAD_FOLDER'])


class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(150), unique=True, nullable=False)
	password = db.Column(db.String(150), nullable=False)
	email = db.Column(db.String(150), unique=True, nullable=False)
	is_admin = db.Column(db.Boolean, default=False)  # New field for admin role
	trainings = db.relationship('Training', backref='user', lazy=True)


class Training(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(100), nullable=False)
	completed_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
	certificate_filename = db.Column(db.String(100), nullable=True)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


def admin_required(func):
	"""Decorator to ensure user is an admin."""

	def wrapper(*args, **kwargs):
		if not current_user.is_admin:
			flash('Access denied. Admins only!', category='danger')
			return redirect(url_for('dashboard'))
		return func(*args, **kwargs)

	wrapper.__name__ = func.__name__
	return wrapper


@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
	trainings = Training.query.all()
	return render_template('admin_dashboard.html', trainings=trainings)


@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
	users = User.query.all()
	return render_template('manage_users.html', users=users)


@app.route('/make_admin/<int:user_id>')
@login_required
@admin_required
def make_admin(user_id):
	user = User.query.get_or_404(user_id)
	user.is_admin = True
	db.session.commit()
	flash(f'{user.username} is now an admin.', category='success')
	return redirect(url_for('manage_users'))


@app.route('/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
	user = User.query.get_or_404(user_id)
	db.session.delete(user)
	db.session.commit()
	flash('User deleted successfully.', category='success')
	return redirect(url_for('manage_users'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
	if request.method == 'POST':
		email = request.form.get('email')
		user = User.query.filter_by(email=email).first()
		if user:
			# Generate reset token
			token = serializer.dumps(email, salt='password-reset-salt')
			reset_link = url_for('reset_password', token=token, _external=True)

			# Send reset email
			msg = Message('Password Reset Request', recipients=[email])
			msg.body = f'Click the link to reset your password: {reset_link}'
			mail.send(msg)
			flash('Password reset email sent!', category='info')
		else:
			flash('Email not found', category='danger')
		return redirect(url_for('login'))
	return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
	try:
		email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
	except SignatureExpired:
		flash('The password reset link has expired.', category='danger')
		return redirect(url_for('forgot_password'))

	if request.method == 'POST':
		password = request.form.get('password')
		user = User.query.filter_by(email=email).first()
		if user:
			user.password = generate_password_hash(password, method='sha256')
			db.session.commit()
			flash('Password reset successfully!', category='success')
			return redirect(url_for('login'))
	return render_template('reset_password.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form.get('username')
		email = request.form.get('email')
		password = request.form.get('password')
		is_admin = request.form.get('is_admin') is not None
		hashed_password = generate_password_hash(password, method='sha256')

		new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
		db.session.add(new_user)
		db.session.commit()

		flash('Account created successfully!', category='success')
		return redirect(url_for('login'))
	return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')

		user = User.query.filter_by(username=username).first()

		if user and check_password_hash(user.password, password):
			login_user(user)
			return redirect(url_for('dashboard'))
		else:
			flash('Login failed. Check your username and password.', category='danger')

	return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
	trainings = Training.query.filter_by(user_id=current_user.id).all()
	return render_template('dashboard.html', trainings=trainings)


@app.route('/add_training', methods=['GET', 'POST'])
@login_required
def add_training():
	if request.method == 'POST':
		title = request.form.get('title')
		completed_date = request.form.get('completed_date')
		certificate = request.files.get('certificate')

		# Handle file upload
		certificate_filename = None
		if certificate:
			certificate_filename = secure_filename(certificate.filename)
			certificate.save(os.path.join(app.config['UPLOAD_FOLDER'], certificate_filename))

		new_training = Training(
			title=title,
			completed_date=datetime.strptime(completed_date, '%Y-%m-%d'),
			certificate_filename=certificate_filename,
			user_id=current_user.id
			)

		db.session.add(new_training)
		db.session.commit()
		flash('Training added successfully!', category='success')
		return redirect(url_for('dashboard'))

	return render_template('add_training.html')


@app.route('/edit_training/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_training(id):
	training = Training.query.get_or_404(id)

	if request.method == 'POST':
		training.title = request.form.get('title')
		training.completed_date = datetime.strptime(request.form.get('completed_date'), '%Y-%m-%d')

		certificate = request.files.get('certificate')
		if certificate:
			certificate_filename = secure_filename(certificate.filename)
			certificate.save(os.path.join(app.config['UPLOAD_FOLDER'], certificate_filename))
			training.certificate_filename = certificate_filename

		db.session.commit()
		flash('Training updated successfully!', category='success')
		return redirect(url_for('dashboard'))

	return render_template('edit_training.html', training=training)


@app.route('/delete_training/<int:id>')
@login_required
def delete_training(id):
	training = Training.query.get_or_404(id)
	db.session.delete(training)
	db.session.commit()
	flash('Training deleted successfully!', category='success')
	return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))


if __name__ == '__main__':
	app.run(debug=True)
