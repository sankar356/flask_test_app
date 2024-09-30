from app.extensions import db
from passlib.hash import pbkdf2_sha256

class Sock(db.Model):
    __tablename__ = 'register_data'
    user_id = db.Column(db.String, primary_key=True)
    user_name = db.Column(db.String, unique=True, nullable=False)
    user_email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    First_name = db.Column(db.String, nullable=False)
    Last_name = db.Column(db.String, nullable=False)

    @staticmethod
    def set_password(password):
        return pbkdf2_sha256.hash(password)
    
    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password)

    def __repr__(self):
        return f'<Sock {self.user_name}>'

class Roles(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.String, primary_key=True)
    role_name = db.Column(db.String())

    def __repr__(self):
        return f'<Roles {self.role_name}>'

class AddUserRole(db.Model):
    __tablename__ = 'user_role_detail'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_id = db.Column(db.String, db.ForeignKey('roles.role_id'))
    user_id = db.Column(db.String, db.ForeignKey('register_data.user_id'))

    def __repr__(self):
        return f'<AddUserRole {self.id}>'

# class Users(db.Model):
#     pass