from flask import Blueprint, request, jsonify
from app.models import Roles
from app.extensions import db, csrf
import uuid

roles_bp = Blueprint('roles', __name__)

@roles_bp.route('/', methods=['GET', 'POST'])
@csrf.exempt
def add_role():
    if request.method == 'POST':
        data = request.get_json()
        new_role = Roles(
            role_id=str(uuid.uuid4()),
            role_name=data['role_name']
        )
        db.session.add(new_role)
        db.session.commit()
        return jsonify({'role_id': new_role.role_id, 'Title': new_role.role_name}), 201
    elif request.method == 'GET':
        roles = Roles
