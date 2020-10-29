# -*- coding: utf-8 -*-
"""
Created on Thu Feb 27 13:29:32 2020

@author: Luis Crespo, Claudia Aragones-Chaves, Javier Camara y Alvaro Reina
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap


from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask_sqlalchemy import SQLAlchemy
from flask_moment import Moment
from datetime import datetime
from flask_login import LoginManager, login_required, login_user, UserMixin, current_user
#from flask_migrate import Migrate
from flask_mail import Mail, Message

import json

with open('/home/lluspel/configuration.json') as json_file:
    configuration = json.load(json_file)


print("FLASK_APP.PY:",__name__)

#########################################################
# DB - CLASSES - START                                  #
#########################################################
from models import models

#########################################################
# DB - CLASSES - END                                    #
#########################################################


#########################################################
# FLASK - FORMS - START                                 #
#########################################################
from forms import forms
#########################################################
# FLASK - FORMS - END                                   #
#########################################################
app = models.app
db = models.db

Bootstrap(app)



moment = Moment(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = configuration['gmail_username']
app.config['MAIL_PASSWORD'] = configuration['gmail_password']

app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[LA AUTENTICASION - Servidor] '
app.config['FLASKY_MAIL_SENDER'] = 'KLODY PAGE <luisutadpy@gmail.com>'

mail = Mail(app)

import random

user = models.User.query.filter_by(role='-1').first()
if (user == None):
    password_hashed = generate_password_hash("admin1234",method='sha256')
    new_user = models.User(username="admin",
                            email=configuration['gmail_username'],
                            password=password_hashed,
                            userhash=str(random.getrandbits(128)),
                            role= '-1',
                            confirmed = 1)
    db.session.add(new_user)
    db.session.commit()


def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject, sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)


@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))


@app.route('/')
def index():
    competitions = models.Competition.query.all()
    predictions = models.Prediction.query.all()
    return render_template("index.html", page="index", current_time=datetime.utcnow(), rows=competitions, predictions=predictions)

@app.route('/login', methods=['GET','POST'])
def login():
    form = forms.LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                user = models.User.query.filter_by(username=form.username.data).first()


                if (user == None):
                    flash('Usuario o contraseñas incorrectos.')
                elif  user.confirmed == 0:
                    flash('La dirección de correo electrónico no ha sido confirmada. Visite su correo electrónico para confirmar su usuario antes de iniciar sesión.')
                elif check_password_hash(user.password,form.password.data):
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('dashboard'))
                else:
                    flash('Acceso denegado: Nombre de usuario o contraseña incorrectos.')
            except:
                flash('Acceso denegado: Nombre de usuario o contraseña incorrectos.')
    else:
        pass
    return render_template("login.html", page="login", form=form)


@app.route('/signup', methods=['GET','POST'])
def signup():
    form = forms.RegisterForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                password_hashed = generate_password_hash(form.password.data,method='sha256')
                new_user = models.User(username=form.username.data,
                                email=form.email.data,
                                password=password_hashed,
                                userhash=str(random.getrandbits(128)),
                                role= form.role.data)
                send_email(new_user.email,'Por favor, confirmar correo.','mail/new_user',user=new_user)
                db.session.add(new_user)
                db.session.commit()
                flash("Usuario creado con éxito.")
                return redirect(url_for('login'))
            except:
                db.session.rollback()
                flash("Algo salió mal. El usuario no ha sido creado. Inténtalo de nuevo.")
    return render_template("signup.html", page="signup", form=form)



@app.route('/confirmuser/<username>/<userhash>', methods=['GET'])
def confirmuser(username,userhash):
    form = forms.LoginForm()
    user = models.User.query.filter_by(username=username).first()
    if user == None:
        flash('URL inválida.')
    elif user.userhash != userhash:
        flash('URL inválida.')
    else:
        user.confirmed = 1
        db.session.commit()
        flash('Correo electrónico validado, por favor, inicie sesión.')

    return render_template("login.html", page="login", form=form)




@app.route('/dashboard')
@login_required
def dashboard():
    competitions = models.Competition.query.all()
    return render_template("dashboard.html", page="dashboard",current_user=current_user, rows=competitions)

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():

    if request.method == 'GET': # Cargando los datos del usuario
        user = models.User.query.filter_by(username=current_user.username).first()
        form = forms.ProfileForm(username=user.username,
                            email=user.email)
    elif request.method == 'POST':  # Actualizar los datos del usuario
        form = forms.ProfileForm()
        if form.validate_on_submit():
            #return("1.2")
            if current_user.username != form.username.data:
                flash('No tienes permiso para actualizar estos datos.')
                return redirect(url_for('index'))
            user = models.User.query.filter_by(username=current_user.username).first()
            user.email = form.email.data
            if form.password.data != '':
                user.password = generate_password_hash(form.password.data,method='sha256')
            db.session.commit()
            flash('Datos actualizados con exito')
    else:
        return redirect(page_not_found('Tipo de llamada inexistente.'))
    return render_template("profile.html", page="profile",current_user=current_user, form=form)


ALLOWED_EXTENSIONS = set(['csv'])

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS

import pandas as pd

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    form = forms.UploadForm()
    if request.method == 'POST': #Recibir el fichero
        num_files = 0
        errors = 0
        if (len(request.files.getlist('file')) != 2):
            flash('Por favor subir 2 ficheros. El fichero de entrenamiento y el fichero de test. Usted ha subido {} ficheros.'.format(len(request.files.getlist('file'))))
            return render_template("upload.html", page="upload",current_user=current_user, form=form)

        file_obj = request.files.getlist('file')[0]
        filename_secured = secure_filename(file_obj.filename)
        if allowed_file(filename_secured) is False:
            flash("Documento {} no es válido. Los documentos válidos son: {}". \
                format(str(filename_secured), ALLOWED_EXTENSIONS))
            errors += 1
        else: # FICHERO APROBADO!
            num_files += 1
            file_path = '/home/lluspel/APP/uploads/temp1.csv'
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            finally:
                file_obj.save(file_path)
        df1 = pd.read_csv(file_path)

        file_obj = request.files.getlist('file')[1]
        filename_secured = secure_filename(file_obj.filename)
        if allowed_file(filename_secured) is False:
            flash("Documento {} no es válido. Los documentos válidos son: {}". \
                format(str(filename_secured), ALLOWED_EXTENSIONS))
            errors += 1
        else: # FICHERO APROBADO!
            num_files += 1
            file_path = '/home/lluspel/APP/uploads/temp2.csv'
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            finally:
                file_obj.save(file_path)
        df2 = pd.read_csv(file_path)

        if len(df1) > len(df2):
            df_train, df_test = df1, df2
        else:
            df_train, df_test = df2, df1

        df_test_public = df_test.iloc[:,:-1]
        df_test_private = df_test.copy().drop(columns=df_test.columns[0:-1])


        competioncode =  ''.join(random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVYXZabcdefghijklmnopqrstuvyxz') for i in range(10))
        filename_prefix = current_user.username+"__" +  str(competioncode)

        df_train.to_csv('/home/lluspel/APP/static/uploads/'+filename_prefix+"__train.csv")
        df_test_public.to_csv('/home/lluspel/APP/static/uploads/'+filename_prefix+"__test.csv")
        df_test_private.to_csv('/home/lluspel/APP/uploads/'+filename_prefix+"__test_private.csv")


        new_competition = models.Competition(competioncode=competioncode,
                        username=current_user.username,
                        title=form.title.data,
                        description=form.description.data)
        db.session.add(new_competition)

        new_df_train = models.File(username=current_user.username,
                        competioncode=competioncode,
                        filename=filename_prefix+"__train.csv"
                        )
        db.session.add(new_df_train)

        new_df_test_public = models.File(username=current_user.username,
                        competioncode=competioncode,
                        filename= filename_prefix+"__test.csv"
                        )
        db.session.add(new_df_test_public)

        new_df_test_private = models.File(username=current_user.username,
                        competioncode=competioncode,
                        filename= filename_prefix+"__test_private.csv"
                        )
        db.session.add(new_df_test_private)

        db.session.commit()
        flash("Competición {} creada con éxito. Ficheros correctos".format(competioncode))

    return render_template("upload.html", page="upload",current_user=current_user,form=form)


@app.route('/createuser', methods=['GET','POST'])
@login_required
def createuser():
    if (current_user.role != '0' and current_user.role != '-1'):
        return render_template("404.html")

    form = forms.RegisterForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                password_hashed = generate_password_hash(form.password.data,method='sha256')
                new_user = models.User(username=form.username.data,
                                email=form.email.data,
                                password=password_hashed,
                                userhash=str(random.getrandbits(128)),
                                role= form.role.data,
                                confirmed=1)
                db.session.add(new_user)
                db.session.commit()
                flash("User created successfully")
                return redirect(url_for('createuser'))
            except:
                db.session.rollback()
                flash("Algo salió mal. El usuario no ha sido creado. Inténtalo de nuevo.")

    users = models.User.query.all()
    return render_template("createuser.html", page="createuser", form=form, current_user=current_user,rows=users)


@app.route('/deleteuser/<id>', methods=['GET','POST'])
@login_required
def deleteuser(id):
    models.User.query.filter_by(id=id).delete()
    db.session.commit()
    return redirect(url_for('createuser'))


@app.route('/edituser/<id>', methods=['GET','POST'])
@login_required
def edituser(id):
    if request.method == 'GET':
        user = models.User.query.filter_by(id=id).first()
        form = forms.ProfileForm(username=user.username,
                            email=user.email)

    elif request.method == 'POST':
        form = forms.ProfileForm()
        if form.validate_on_submit():
            user = models.User.query.filter_by(id=id).first()
            user.email = form.email.data
            user.username = form.username.data
            if form.password.data != '':
                user.password = generate_password_hash(form.password.data,method='sha256')
            db.session.commit()
            flash('Datos actualizados con exito')
    else:
        return redirect(page_not_found('Tipo de llamada inexistente.'))
    return render_template("edituser.html", page="edituser",current_user=current_user,rows=user, form=form)


@app.route('/competition', methods=['GET','POST'])
@login_required
def competition():
    if (current_user.role != '0' and current_user.role != '-1'):
        competitions = models.Competition.query.filter_by(username=current_user.username).all()
    else:
        competitions = models.Competition.query.all()
    return render_template("competition.html", page="competition",current_user=current_user,rows=competitions)


@app.route('/edit/<competioncode>', methods=['GET','POST'])
@login_required
def edit(competioncode):
    if request.method == 'GET':
        competitions = models.Competition.query.filter_by(competioncode=competioncode).first()
        form = forms.EditForm(username=competitions.username, title=competitions.title,
                            description=competitions.description)

    elif request.method == 'POST':
        form = forms.EditForm()
        if form.validate_on_submit():
            competitions = models.Competition.query.filter_by(competioncode=competioncode).first()
            competitions.title = form.title.data
            competitions.description = form.description.data
            db.session.commit()
            flash('Datos actualizados con exito')
    else:
        return redirect(page_not_found('Tipo de llamada inexistente.'))

    competitions = models.Competition.query.filter_by(competioncode=competioncode).first()
    return render_template("edit.html", page="edit",current_user=current_user,rows=competitions,form=form)


@app.route('/delete/<competioncode>', methods=['GET','POST'])
@login_required
def delete(competioncode):
    models.Competition.query.filter_by(competioncode=competioncode).delete()
    db.session.commit()
    return redirect(url_for('competition'))


@app.route('/files/<competioncode>', methods=['GET','POST'])
@login_required
def files(competioncode):
    files = models.File.query.filter_by(competioncode=competioncode).all()
    return render_template("files.html", page="files",current_user=current_user,rows=files)


@app.route('/code/<competioncode>', methods=['GET','POST'])
@login_required
def code(competioncode):
    competioncode = competioncode.replace(".py","")
    competion = models.Competition.query.filter_by(competioncode=competioncode).first()
    return render_template("competition_template.py",competion=competion,current_user=current_user)


@app.route('/ranking/<competioncode>', methods=['GET'])
@login_required
def ranking(competioncode):
    predictions = models.db.session.query(models.Prediction.username, models.db.func.max(models.Prediction.score).label('best_score')).filter_by(competioncode=competioncode).group_by(models.Prediction.username).all()
    return render_template("ranking.html", page="ranking",current_user=current_user, rows=predictions, competioncode=competioncode)



###############################################################################################################
#         API-REST -                                                                                START    #
###############################################################################################################
from flask_httpauth import HTTPBasicAuth
from flask import abort, jsonify, make_response
auth = HTTPBasicAuth()

API_USER_SESSION = {}

@auth.verify_password
def verify_pw(username, password):
    global API_USER_SESSION
    try:
        API_USER_SESSION["username"]= username

        user = models.User.query.filter_by(username=username).first()
        if user.password == password:
            return True
    except:
        abort(401)
    return False

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Acceso no autorizado'}), 401)

@app.route('/favicon.ico')
def favicon():
    return("")


from sklearn.metrics import roc_auc_score
@app.route('/uploadpredictions/<competioncode>', methods=['POST'])
@auth.login_required
def uploadpredictions(competioncode):
    global API_USER_SESSION


    if 'file' not in request.files:
        return ('ERROR: no file part')
    file_obj = request.files['file']
    if file_obj.filename == '':
        return ('ERROR: no selected file')


    competition = models.Competition.query.filter_by(competioncode=competioncode).first()
    df_private = pd.read_csv('./uploads/{}__{}__test_private.csv'.format(competition.username,competioncode))
    df_private.columns = ['id','real']
    df_private.index = df_private.id


    file_path = '/home/'+configuration['mysql_username']+'/APP/uploads/submission_temp.csv'
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
    finally:
        file_obj.save(file_path)

    try:
        df_submission = pd.read_csv(file_path)
        df_submission.index = df_submission.id
    except:
        return ('ERROR: file empty or not a valid csv')

    df_merged = pd.merge(df_private, df_submission, left_index=True, right_index=True, how='left')
    df_merged.fillna(0, inplace=True)
    gini_score = float(2*roc_auc_score(df_merged.real, df_merged.pred)-1)


    df_merged['pred_class'] = 1.0*(df_merged.pred>=0.5)
    accuracy_score = sum(df_merged.real == df_merged.pred_class)/len(df_merged)
    new_prediction1 = models.Prediction(competioncode = competioncode, username = API_USER_SESSION['username'], score = gini_score, metrica = 'gini')
    new_prediction2 = models.Prediction(competioncode = competioncode, username = API_USER_SESSION['username'], score = accuracy_score, metrica = 'accuracy')

    db.session.add(new_prediction1)
    db.session.add(new_prediction2)
    db.session.commit()

    return("Enhorabuena has enviado una predicción a la competición {} - el gini obtenido es = {} y el accuracy es {}".format(competioncode, gini_score, accuracy_score))


@app.route('/logout')
@login_required
def logout():
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html")


if __name__ == '__main__':
    app.run(debug=True)

