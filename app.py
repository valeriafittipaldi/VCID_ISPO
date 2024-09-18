from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisshouldbeasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://rezeptuser:1234@localhost/rezeptdb'
app.config['UPLOAD_FOLDER'] = './static/uploads'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Datenbank-Modelle
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password_hash = db.Column(db.String(200))

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    ingredients = db.Column(db.Text)
    instructions = db.Column(db.Text)
    image = db.Column(db.String(100))

# Flask-Login Setup
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# FlaskForm-Formulare
class LoginForm(FlaskForm):
    username = StringField('Benutzername', validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField('Passwort', validators=[InputRequired(), Length(min=4, max=50)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Benutzername', validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField('Passwort', validators=[InputRequired(), Length(min=4, max=50)])
    submit = SubmitField('Registrieren')

class RecipeForm(FlaskForm):
    title = StringField('Titel', validators=[InputRequired()])
    ingredients = TextAreaField('Zutaten', validators=[InputRequired()])
    instructions = TextAreaField('Zubereitung', validators=[InputRequired()])
    image = FileField('Bild')
    submit = SubmitField('Rezept erstellen')

# Routen
@app.route('/')
def index():
    recipes = Recipe.query.all()
    return render_template('index.html', recipes=recipes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

        else:
            flash('Login fehlgeschlagen. Bitte überprüfe deine Daten.')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registrierung erfolgreich! Bitte logge dich ein.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
#@login_required
def dashboard():
    form = RecipeForm()
    if form.validate_on_submit():
        image_file = None
        if form.image.data:
            image = form.image.data
            image_file = f'uploads/{image.filename}'
            image.save(image_file)

        new_recipe = Recipe(
            title=form.title.data,
            ingredients=form.ingredients.data,
            instructions=form.instructions.data,
            image=image_file
        )
        db.session.add(new_recipe)
        db.session.commit()
        flash('Rezept erfolgreich erstellt!')
        return redirect(url_for('dashboard'))
    recipes = Recipe.query.all()
    return render_template('dashboard.html', form=form, recipes=recipes)

@app.route('/edit_recipe/<int:id>', methods=['GET', 'POST'])
#@login_required
def edit_recipe(id):
    recipe = Recipe.query.get_or_404(id)
    form = RecipeForm()

    if form.validate_on_submit():
        if form.title.data:
            recipe.title = form.title.data
        if form.ingredients.data:
            recipe.ingredients = form.ingredients.data
        if form.instructions.data:
            recipe.instructions = form.instructions.data
        if form.image.data:
            image = form.image.data
            image_file = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(image_file)
            recipe.image = image.filename

        db.session.commit()
        flash('Rezept erfolgreich aktualisiert!')
        return redirect(url_for('dashboard'))

    form.title.data = recipe.title
    form.ingredients.data = recipe.ingredients
    form.instructions.data = recipe.instructions
    form.submit.label.text = "Rezept aktualisieren"

    return render_template('edit_recipe.html', form=form, recipe=recipe)

@app.route('/delete_recipe/<int:id>', methods=['POST'])
#login_required
def delete_recipe(id):
    recipe = Recipe.query.get_or_404(id)
    db.session.delete(recipe)
    db.session.commit()
    flash('Rezept erfolgreich gelöscht!')
    return redirect(url_for('dashboard'))




@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
