import os
user = "root"
pin = "Admin"
host = "localhost"
port = "3308"
db_name = "user_data"

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_default_secret_key')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'mysql+pymysql://{user}:{pin}@{host}:{port}/{db_name}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwtkey')