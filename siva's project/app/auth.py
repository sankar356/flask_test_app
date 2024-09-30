from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from app.extensions import csrf, blacklist
from app.models import Sock

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login/', methods=['POST'])
@csrf.exempt
def user_login():
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

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
@csrf.exempt
def logout():
    jti = get_jwt()["jti"]
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

@auth_bp.route('/csrf-token', methods=['GET'])
def csrf_token():
    token = csrf.generate_csrf()
    response = make_response(jsonify({'csrf_token': token}))
    response.set_cookie('csrf_token', token)
    return response
