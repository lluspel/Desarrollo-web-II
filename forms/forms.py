from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import InputRequired, Length, Email, NoneOf

class LoginForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4,max=15)])
    password = PasswordField('Contraseña',validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Recuérdame')

class RegisterForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4, max=15),
                                                   NoneOf(['pepito','juanito'],
                                                          message='Usuario ya existe')])
    password = PasswordField('Contraseña',validators=[InputRequired(), Length(min=8, max=80)])

    email = StringField('E-mail',validators=[InputRequired(), Email(message='Email inválido') ,
                                             Length(max=50)])
    role = SelectField('Role', choices=[("1", 'Player'),
                                        ("2", 'Competitor')])


class ProfileForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4, max=15),
                                                   NoneOf(['pepito','juanito'],
                                                          message='Usuario ya existe')])

    email = StringField('E-mail',validators=[InputRequired(), Email(message='Invalid email') ,
                                             Length(max=50)])
    password = PasswordField('Contraseña')


class UploadForm(FlaskForm):
    title = StringField('Titulo de la competición',validators=[InputRequired(), Length(min=4,max=15)])
    description = StringField('Descripción',validators=[InputRequired(), Length(min=4, max=200)])


class EditForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4, max=15),
                                               NoneOf(['pepito','juanito'],
                                                      message='Usuario ya existe')])
    title = StringField('Titulo de la competición',validators=[InputRequired(), Length(min=4,max=30)])
    description = StringField('Descripción',validators=[InputRequired(), Length(min=4, max=200)])
