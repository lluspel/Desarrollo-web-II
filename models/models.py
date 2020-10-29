from flask import Flask
from flask_login import UserMixin
from flask_sqlalchemy  import SQLAlchemy
import json


#print("MODELS.PY:",__name__)
app = Flask('flask_app')

with open('/home/lluspel/configuration.json') as json_file:
    configuration = json.load(json_file)

app.config['SECRET_KEY'] = configuration['SECRET_KEY']



SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username=configuration['mysql_username'],
    password=configuration['mysql_password'],
    hostname=configuration['mysql_hostaname'],
    databasename=configuration['mysql_databasename'],
)


app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    confirmed = db.Column(db.Integer, default=0)
    userhash = db.Column(db.String(50))
    role = db.Column(db.String(4), default=1)

from datetime import datetime
class File(UserMixin, db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    competioncode = db.Column(db.String(15))
    filename = db.Column(db.String(50))
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)

class Competition(UserMixin, db.Model):
    __tablename__ = 'competitions'
    id = db.Column(db.Integer, primary_key=True)
    competioncode = db.Column(db.String(15), unique=True)
    username = db.Column(db.String(15))
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    title = db.Column(db.String(20), default='Nada')
    description = db.Column(db.String(200), default='.....')


class Prediction(UserMixin, db.Model):
    __tablename__ = 'predictions'
    id = db.Column(db.Integer, primary_key=True)
    competioncode = db.Column(db.String(15))
    username = db.Column(db.String(15))
    score = db.Column(db.Float)
    metrica = db.Column(db.String(15))
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
