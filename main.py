from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField
from wtforms.validators import InputRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy import func
from authlib.integrations.flask_client import OAuth
import bcrypt
import requests
from flask_mail import Mail
from email.message import EmailMessage
import random
import smtplib
import ssl

app = Flask(__name__)
app.app_context().push()

app.config['SECRET_KEY'] = 'SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appwork.db'

db = SQLAlchemy(app)

oauth = OAuth(app)

mail = Mail(app)

"<-----------------Flask Form--------------->"

class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Length(min=4, max=40)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=50)])

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Length(min = 4, max = 40)])
    password = PasswordField('password', validators=[InputRequired(), Length(min = 8, max = 50)])
    confirm = PasswordField('confirm', validators=[InputRequired(), Length(min=8, max=50)])

class WorksForm(FlaskForm):
    title = StringField('title', validators=[InputRequired()])
    content = StringField('content', validators=[InputRequired()])
    category = StringField('category', validators=[InputRequired()])
    price = FloatField('price', validators=[InputRequired()])
    image = StringField('imageUrl', validators=[InputRequired()])

"<-----------------SQLAlchemy database ----------------->"

class Accounts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String, unique = True, nullable = True)
    password = db.Column(db.String, nullable = True)
    works = db.relationship('Works', backref = 'accounts', passive_deletes=True)
    admin = db.Column(db.Boolean, default = False, nullable = True)

class Works(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String)
    content = db.Column(db.String)
    category = db.Column(db.String)
    price = db.Column(db.Float)
    image = db.Column(db.String)
    author = db.Column(db.Integer, db.ForeignKey('accounts.id', ondelete = "CASCADE"), nullable = False)
    date = db.Column(db.DateTime(timezone = True), default = func.now())

with app.app_context():
    db.create_all()

"<-----------------Login Manager --------------->"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'email'

@login_manager.user_loader
def load_user(user_id):
    return Accounts.query.get(int(user_id))

"<----------------- Google Auth ----------------->"

google = oauth.register(

)

"<----------------- GitHub Auth ----------------->"

github = oauth.register (

)

"<----------------- Main --------------->"

@app.route('/account', methods = ['GET', 'POST'])
def account():
    form = LoginForm()
    if form.validate_on_submit():
        checkAccount = Accounts.query.filter_by(email = form.email.data).first()
        if checkAccount:
            if bcrypt.checkpw((form.password.data).encode('utf-8'), checkAccount.password):
                login_user(checkAccount)
                return redirect(url_for("home"))
            else:
                flash("Your password is incorrect")
        else:
            flash("This user doesn't exist")
    return render_template('Account.html', form = form)

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if Accounts.query.filter_by(email = form.email.data).first():
            flash("This email is already used")
        else:
            if form.password.data == form.confirm.data:
                cryptedPassword = bcrypt.hashpw(password=(form.password.data).encode('utf-8'), salt=bcrypt.gensalt())
                newAccount = Accounts(email = form.email.data, password = cryptedPassword)
                db.session.add(newAccount)
                db.session.commit()
                login_user(newAccount)
                return redirect(url_for("home"))
            else:
                flash("Confirm password is incorrect")
    return render_template('Register.html', form = form)

@app.route('/account/google')
def loginGoogle():
    google = oauth.create_client('google')
    redirect_uri = url_for('googleAuthorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/account/google/authorize')
def googleAuthorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    checkAccount = Accounts.query.filter_by(email = google.get('userinfo').json()['email']).first()
    if checkAccount is not None:
        login_user(checkAccount)
        return redirect(url_for("home"))
    else:
        cryptedPassword = bcrypt.hashpw(password= (google.get('userinfo').json()['id']).encode('utf-8'), salt = bcrypt.gensalt())
        newAccount = Accounts(email = google.get('userinfo').json()['email'], password = cryptedPassword)
        db.session.add(newAccount)
        db.session.commit()
        login_user(newAccount)
        return redirect(url_for("home"))

@app.route('/account/github')
def github_login():
    github = oauth.create_client('github')
    redirect_uri = url_for('githubAuthorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/account/github/authorize')
def githubAuthorize():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    checkAccount = Accounts.query.filter_by(email=github.get('user').json()['login']).first()
    if checkAccount is not None:
        login_user(checkAccount)
        return redirect(url_for("home"))
    else:
        cryptedPassword = bcrypt.hashpw(password=(str(github.get('user').json()['id'])).encode('utf-8'), salt=bcrypt.gensalt())
        newAccount = Accounts(email=github.get('user').json()['login'], password=cryptedPassword)
        db.session.add(newAccount)
        db.session.commit()
        login_user(newAccount)
        return redirect(url_for("home"))

@app.route('/forgot', methods = ['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        emailTo = request.form['email']
        if Accounts.query.filter_by(email=emailTo).first():
            email = Accounts.query.filter_by(email=emailTo).first()
            
            codeList = []
            for i in range(6):
                codeList.append(random.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
            code = ''
            for i in codeList:
                code += str(i)
            em = EmailMessage()
            em['From'] = email_sender
            session['email'] = email.email
            session['code'] = int(code)
            em['To'] = email.email
            em['Subject'] = 'Your verification code'
            em.set_content('Please confirm your verification code ' + code)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(email_sender, email_password)
                smtp.sendmail(email_sender, request.form['email'], em.as_string())
            return redirect(url_for("smsVerification"))
        else:
            flash("This email doesn't exist")
    return render_template('ForgotPassword.html')

@app.route('/forgot/sms', methods = ['GET', 'POST'])
def smsVerification():
    if request.method == 'POST':
        if int(request.form['sms']) == int(session['code']):
            return redirect(url_for("changePassword"))
        else:
            flash("SMS Code is incorrect")
    return render_template('SMSVerification.html')

@app.route('/forgot/sms/changePassword', methods = ['GET', 'POST'])
def changePassword():
    if request.method == 'POST':
        if request.form['password'] == request.form['confirm']:
            checkAccount = Accounts.query.filter_by(email = session['email']).first()
            checkAccount.password = bcrypt.hashpw(password= (request.form['password']).encode('utf-8'), salt = bcrypt.gensalt())
            db.session.commit()
            return redirect(url_for("account"))
        else:
            flash("Confirm password is incorrect")
    return render_template('ChangePassword.html')

@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route('/myworks')
def myworks():
    works = Works.query.filter(Works.author == current_user.id).all()
    return render_template('MyWorks.html', works = works)

@app.route('/addwork', methods = ['GET', 'POST'])
def addwork():
    form = WorksForm()
    if form.validate_on_submit():
        newWork = Works(title = form.title.data, content = form.content.data,
                        category = form.category.data, price = form.price.data,
                        image = form.image.data, author = current_user.id)
        db.session.add(newWork)
        db.session.commit()
        return redirect(url_for("myworks"))
    return render_template('AddWork.html', form = form)

@app.route('/delete/<int:id>')
def delete(id):
    post = Works.query.filter_by(id = id).first()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("myworks"))

@app.route('/edit/<int:id>', methods = ['GET', 'POST'])
def edit(id):
    form = WorksForm()
    if form.validate_on_submit():
        workUpdate = Works.query.filter_by(id=id).first()
        workUpdate.title = form.title.data
        workUpdate.content = form.content.data
        workUpdate.category = form.category.data
        workUpdate.image = form.image.data
        workUpdate.price = form.price.data
        db.session.commit()
        return redirect(url_for("myworks"))
    return render_template('Edit.html', form = form)

@app.route('/')
def home():
    works = Works.query.all()
    category = Works.query.all()
    return render_template('Home.html', works = works, category = category)

@app.route('/filter/<category>')
def filter(category):
    works = Works.query.filter_by(category = category).all()
    category = Works.query.all()
    return render_template('Home.html', works = works, category = category)

"<----------------- Admin ----------------->"

@app.route('/admin', methods = ['GET', 'POST'])
def admin():
    form = RegisterForm()
    if form.validate_on_submit():
        if Accounts.query.filter_by(email=form.email.data).first():
            flash("This email is already used")
        else:
            if form.password.data == form.confirm.data:
                cryptedPassword = bcrypt.hashpw(password=(form.password.data).encode('utf-8'), salt=bcrypt.gensalt())
                newAccount = Accounts(email=form.email.data, password=cryptedPassword, admin = True)
                db.session.add(newAccount)
                db.session.commit()
                login_user(newAccount)
                return redirect(url_for("home"))
            else:
                flash("Confirm password is incorrect")
    return render_template('AdminRegistration.html', form=form)

if __name__ == '__main__':
    app.run(debug = True, host = 'localhost', port = 3000)