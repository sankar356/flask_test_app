from flask import *
import jwt
from sqlalchemy.exc import SQLAlchemyError 
from flask_sqlalchemy import SQLAlchemy
from datetime import *
from flask_wtf import CSRFProtect 
from flask_login import LoginManager
from flask_bootstrap import Bootstrap5
import uuid
from sqlalchemy.orm.exc import NoResultFound
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from passlib.hash import pbkdf2_sha256
from functools import wraps

# end import-------------------------

app = Flask(__name__)

user = "root"
pin = "Admin"
host = "localhost"
port = "3308"
db_name = "user_data"
blacklist = set()
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{user}:{pin}@{host}:{port}/{db_name}"
jwt = JWTManager(app)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)
app.config['SECRET_KEY']="1095SiVA"
app.config["JWT_SECRET_KEY"] = 'jwtkey'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
csrf = CSRFProtect()
login_manager = LoginManager(app)
jwt = JWTManager(app)

bootstrap = Bootstrap5(app)
# Flask-WTF requires this line
csrf = CSRFProtect(app)

import secrets
foo = secrets.token_urlsafe(16)
app.secret_key = foo
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'error': 'token is missing'}), 403
        try:
            jwt.decode(token, app.config['secret_key'], algorithms="HS256")
        except Exception as error:
            return jsonify({'error': 'token is invalid/expired'})
        return f(*args, **kwargs)
    return decorated

# table for user
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
    

# table for roles
class Roles(db.Model):
     __tablename__ = 'roles'

     role_id = db.Column(db.String, primary_key=True)
     role_name = db.Column(db.String())

     def __repr__(self):
        return f'<Roles {self.role_name}>'

#hear use a model class for user_role_details
class AddUserRole(db.Model):
     __tablename__ = 'user_role_detail'

     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
     role_id = db.Column(db.String, db.ForeignKey('roles.role_id'))
     user_id = db.Column(db.String, db.ForeignKey('register_data.user_id'))

     def __repr__(self):
        return f'<AddUserRole {self.id}>'
     

def get_db():
    with app.app_context():
        db.create_all()


myuuid =str(uuid.uuid4())

    
@app.route('/edituser/<user_id>',methods=['PUT','DELETE'])
@csrf.exempt
def editUser(user_id):
    user = Sock.query.get(user_id)
    if not user:
        return jsonify({'error': 'Book not found'}), 404
    
    if request.method == 'PUT':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid input'}), 400
        
        user.user_name = data.get('user_name', user.user_name)
        user.user_email = data.get('user_email', user.user_email)
        user.password = data.get('password', user.password)
        user.First_name = data.get('First_name', user.First_name)
        user.Last_name = data.get('Last_name', user.Last_name)
        
        db.session.commit()
        return jsonify({
            'user_name': user.user_name,
            'user_email': user.user_email,
            'password': user.password,
            'First_name': user.First_name,
            'Last_name': user.Last_name,
            
        })
    elif request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'user deleted successfully'}), 200

    else:
        return jsonify({'error': 'Method not allowed'}), 405
# for log out
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist
    # ---------------------------------

def staff_required(name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                current_user_id = get_jwt_identity()
                user_role = db.session.query(AddUserRole).join(Roles).filter(
                    AddUserRole.user_id == current_user_id,
                    Roles.role_name == name
                ).first()
                if user_role is None:
                    return jsonify({"error": "Forbidden"}), 403
                return f(*args, **kwargs)
            except NoResultFound:
                return jsonify({"error": "Forbidden"}), 403
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        return decorated_function
    return decorator




@app.route('/role/', methods=['GET', 'POST'])
@csrf.exempt
def add_role():
    if request.method == 'POST':
        data = request.get_json()
        new_role = Roles(
            role_id=int(uuid.uuid4().int >> 64),
            role_name=data['role_name']
        )
        db.session.add(new_role)
        db.session.commit()
        return jsonify({'role_id': new_role.role_id, 'Title': new_role.role_name}), 201
    elif request.method == 'GET':
        roles = Roles.query.all()
        return jsonify([{
            'role_id': role.role_id,
            'Title': role.role_name
        } for role in roles])
    else:
        return 'Method Not Allowed', 405


     
def load_user(user_id):
    return Sock.query.get(user_id)

def add_user_role_details(user_id, roles):
    for role_name in roles:
        role = Roles.query.filter_by(role_name=role_name).first()
        if role:
            user_role = AddUserRole(role_id=role.role_id, user_id=user_id)
            db.session.add(user_role)
    db.session.commit()

# hear we add user
@app.route('/addnewuser/', methods=['GET', 'POST']) 
@csrf.exempt
@jwt_required()
@staff_required('staff')
def add_new_user():
    
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid input'}), 400

        user_name = data.get('user_name')
        user_email = data.get('user_email')
        password = data.get('password')
        first_name = data.get('First_name')
        last_name = data.get('Last_name')

        if not all([user_name, user_email, password, first_name, last_name]):
            return jsonify({'error': 'Missing fields'}), 400

        user_id = str(uuid.uuid4())  # Generate a new unique ID
        hashed_password = Sock.set_password(password)
        new_user = Sock(user_id=user_id, user_name=user_name, password=hashed_password, user_email=user_email, First_name=first_name, Last_name=last_name)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            role_assignment_status = adduser_role_details(user_id)
            if role_assignment_status == 500:
                return jsonify({'error': 'Error assigning roles'}), 500
            return jsonify({'user_id': new_user.user_id, 'user_name': new_user.user_name}), 201
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        
    elif request.method == 'GET':
        users = Sock.query.all()
        
        return jsonify([{
            'user_id': user.user_id,
            'user_name': user.user_name,
            'user_email': user.user_email,
            'password': user.password,
            'First_name': user.First_name,
            'Last_name': user.Last_name,
        } for user in users])

    else:
        return 'Method Not Allowed', 405


# login hear
@app.route('/login/', methods=['GET', 'POST'])
@csrf.exempt
def userLogin():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid input'}), 400

    user_email = data.get('user_email')
    password = data.get('password')

    if not all([user_email, password]):
        return jsonify({'error': 'Missing fields'}), 400

    user = Sock.query.filter_by(user_email=user_email).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.user_id)
        return jsonify({'message': 'Login success', 'user_name': user.user_name, 'access_token': access_token}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# log out hear
@app.route('/logout/', methods=['POST'])
@jwt_required()
@csrf.exempt
def logout():
    jti = get_jwt()["jti"]
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200
# hear we can add user role and role

def adduser_role_details(user_id):
    staff_roles = db.session.query(Roles).filter(Roles.role_name == "staff").all()
    role_ids = [role.role_id for role in staff_roles]

    try:
        for role_id in role_ids:
            new_role = AddUserRole(user_id=user_id, role_id=role_id)
            db.session.add(new_role)
        db.session.commit()
        return 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return 500
    

# create tokeen hear
@app.route('/csrf-token', methods=['GET'])
def csrf_token():
    token = csrf.generate_csrf()
    response = make_response(jsonify({'csrf_token': token}))
    response.set_cookie('csrf_token', token)
    return response

if __name__ == '__main__':
    app.run(debug=True)





@app.route('/user/<name>')

def user(name):
    return "<h1>vanakam ya mapla{}</h1>".format(name)






app.app_context().push()


