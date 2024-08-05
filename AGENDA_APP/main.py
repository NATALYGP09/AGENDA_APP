from flask import Flask, session, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contactos.sqlite'
app.config['SECRET_KEY'] = '5dfc118a7256f56d0fc1fcbef8759ccd'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos de base de datos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False, unique=True)
    nombre = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombre = db.Column(db.Text, nullable=False)
    telefono = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()
    try:
        obj = User(email='admin@admin.com', password=generate_password_hash('12345'), nombre='Admin')
        db.session.add(obj)
        db.session.commit()
    except:
        pass

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas seguras
@app.route("/update_contact/<int:id>", methods=['GET', 'POST'])
@login_required
def update_contact(id):
    contact = Contact.query.get_or_404(id)
    if request.method == 'POST':
        contact.nombre = request.form.get('nombre')
        contact.telefono = request.form.get('telefono')
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('update_contact.html', contact=contact)

@app.route("/delete_contact/<int:id>")
@login_required
def delete_contact(id):
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    return redirect(url_for('index'))

@app.route("/add_contact", methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        telefono = request.form.get('telefono')
        new_contact = Contact(nombre=nombre, telefono=telefono)
        db.session.add(new_contact)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_contact.html')

@app.route("/")
@login_required
def index():
    contacts = Contact.query.all()
    return render_template('index.html', contacts=contacts)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        usuario = User.query.filter_by(email=email).first()
        if usuario and check_password_hash(usuario.password, password):
            login_user(usuario)
            return redirect(url_for('index'))
        else:
            error = "Usuario o contraseña incorrectos"
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        nombre = request.form.get('nombre')
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password, nombre=nombre)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/update_profile", methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        email = request.form.get('email')
        nombre = request.form.get('nombre')
        password = request.form.get('password')
        new_password = request.form.get('new_password')

        user = User.query.filter_by(id=current_user.id).first()

        if user and check_password_hash(user.password, password):
            if new_password:
                user.password = generate_password_hash(new_password)
            user.email = email
            user.nombre = nombre
            db.session.commit()
            flash('Perfil actualizado con éxito', 'success')
            return redirect(url_for('index'))
        else:
            flash('Contraseña actual incorrecta', 'danger')
    return render_template('update_profile.html', user=current_user)

if __name__ == "__main__":
    app.run(debug=True)
