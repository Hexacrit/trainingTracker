Here's a sample `README.md` for your Flask CRUD app with user authentication, training tracking, admin features, and password reset functionality:

---

# Flask Training Management App

This is a simple CRUD (Create, Read, Update, Delete) web application built with Flask, allowing multiple users to log in and track their completed trainings. The app supports user registration, login, password reset, and administrator features for user management. Users can optionally upload certificates for each completed training.

## Features

- **User Authentication**: Users can register, log in, and reset their passwords via email.
- **Admin Role**: Admin users can manage all users and view their training records.
- **Training Tracking**: Users can add, view, update, and delete their completed trainings.
- **Certificate Uploads**: Users can upload certificates for each training.
- **Password Reset**: Users can reset their passwords through email verification.

## Project Structure

```
/flask_crud_app/
    /static/                # Static files like CSS, images
    /templates/             # HTML templates
    /uploads/               # Directory for uploaded certificates
    app.py                  # Main Flask application
    config.py               # Configuration file (optional)
    models.py               # Database models (defined within app.py)
    database.db             # SQLite database (generated automatically)
    requirements.txt        # List of dependencies
    README.md               # Project documentation
```

## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/yourusername/flask-training-app.git
cd flask-training-app
```

2. **Create a virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

4. **Set up the database:**

Open a Python shell and initialize the database:

```bash
from app import db
db.create_all()
```

5. **Configure Email for Password Reset:**

In `app.py`, configure Flask-Mail settings:

```python
app.config['MAIL_SERVER'] = 'smtp.your-email-provider.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'
```

Replace the placeholders with your email provider's SMTP settings and your credentials.

6. **Run the Application:**

```bash
flask run
```

The app will now be available at `http://127.0.0.1:5000`.

## Usage

### User Registration

- Navigate to `/register` to create a new user account.
- Admins can be created by checking the "Make Admin" option during registration, or existing users can be promoted by an admin.

### User Login

- Go to `/login` to log in with your username and password.
- After logging in, you'll be redirected to the dashboard where you can manage your trainings.

### Dashboard

- Regular users can add, view, edit, and delete their own trainings.
- Admin users can view all user trainings from the `/admin_dashboard`.

### Admin Features

Admins can:
- View all users' trainings from the `/admin_dashboard`.
- Manage users by visiting `/manage_users`, where they can promote users to admin or delete accounts.

### Password Reset

If you forget your password:
1. Go to `/forgot_password` and enter your registered email address.
2. You will receive an email with a password reset link.
3. Follow the link and set a new password.

### File Uploads

When adding or updating a training, users can upload an optional training certificate (PDF, image, etc.). Uploaded files will be stored in the `/uploads` directory.

## Admin Role

The admin role allows users to manage other users and view all training records. You can create an admin user during registration by selecting the "Make Admin" option, or an existing user can be promoted to admin by another admin.

## Routes

- `/register`: Register a new user account.
- `/login`: Log in with your username and password.
- `/logout`: Log out of your account.
- `/dashboard`: View and manage your own training records.
- `/add_training`: Add a new training record.
- `/edit_training/<int:id>`: Edit an existing training record.
- `/delete_training/<int:id>`: Delete a training record.
- `/forgot_password`: Request a password reset.
- `/reset_password/<token>`: Reset your password using the link sent via email.
- `/admin_dashboard`: Admin view to see all user trainings.
- `/manage_users`: Admin view to manage users (promote to admin, delete users).

## License

This project is licensed under the MIT License.

---

Feel free to customize the `README.md` with additional details, such as specific instructions for deploying the app, testing, or contributing to the project.