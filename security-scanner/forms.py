from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo


class SignupForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(message="Enter a valid email address.")])
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, message="Use at least 8 characters.")],
    )
    confirm = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(message="Enter a valid email address.")])
    password = PasswordField("Password", validators=[DataRequired()])


class ScheduleForm(FlaskForm):
    target_url = StringField("Target URL", validators=[DataRequired()])
    frequency = SelectField("Frequency", choices=[("daily", "Daily"), ("weekly", "Weekly")])
    notify_email = BooleanField("Email me the results", default=True)
