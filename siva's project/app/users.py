from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy.exc import SQLAlchemyError
from app.models import Sock, AddUserRole, Roles
from app.extensions import db, csrf
import uuid

users_bp = Blueprint('users', __name__)

@users_bp.route('/addnewuser/', methods=['GET','POST'])
@csrf.exempt
@jwt_required()
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

@users_bp.route('/edituser/<user_id>', methods=['PUT', 'DELETE'])
@csrf.exempt
def edit_user(user_id):
    user = Sock.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if request.method == 'PUT':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid input'}), 400

        user.user_name = data.get('user_name', user.user_name)
        user.user_email = data.get('user_email', user.user_email)
        user.password = data.get('password', user.password)
        user.First_name = data.get('First_name', user.First_name)
        user.Last_name = data.get('Last_name', user.Last_name)

        try:
            db.session.commit()
            return jsonify({
                'user_name': user.user_name,
                'user_email': user.user_email,
                'password': user.password,
                'First_name': user.First_name,
                'Last_name': user.Last_name,
            })
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    elif request.method == 'DELETE':
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'}), 200
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    else:
        return jsonify({'error': 'Method not allowed'}), 405

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
