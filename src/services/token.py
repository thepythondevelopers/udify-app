from itsdangerous import URLSafeTimedSerializer
from flask import current_app

# to genereate an email confirmation token, to verify the users email
def generate_email_confirmation_token(email):

    serilalizer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    print(f"Serial dumps: {serilalizer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])}")
    return serilalizer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

# to verify the email token
def confirm_email_confirmation_token(token, expiration=3600):

    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token, 
            salt = current_app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except Exception as error:
        print(error)
        return False
    return email