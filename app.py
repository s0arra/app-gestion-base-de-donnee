from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity 
app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'hhyyfbnhvfgvfedfyhujnbbvftgh£h'
jwt = JWTManager(app)

mongo_uri = 'mongodb://root:rootPass@185.2.101.12/'
database_name = "test"

client = MongoClient(mongo_uri)
db = client[database_name]
salt = bcrypt.gensalt(14)

def hash_password(password):
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()


def check_password(entered_password, hashed_password):
    return bcrypt.checkpw(entered_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.route('/accounts', methods=['POST'])
def add_accounts():
    try:
        data = request.json
        employees = db['employees']
        employees_id = employees.insert_one({
            "fullName": data['fullName'],
            "matricule": data['matricule'],
            "phoneNumber": data['phonenumber'],
            "birthDate": data['birthDate'],
            "embaucheDate": data['embaucheDate'],
            "contractType": data['contractType'],
            "Rib": data['Rib'],
            "CIN": data['CIN'],
            "Poste": data['Poste'],
            "sold": data['sold'],
            "address": data['address'],
            "birthPlace": data['birthPlace']

        }).inserted_id
        return {'id': str(employees_id)}
    except Exception as e:
        return {'error': str(e)}

#admin register
@app.route('/admin/register', methods=['POST'])
@jwt_required()
def admin_register():
    data = request.get_json()
    current_user = get_jwt_identity()
    user = db["accounts"].find_one({"idEmployee": current_user, "Role": "SUPER_ADMIN"})
    if not user:
        return jsonify({'error': 'Authentication failed. Admin token required.'}), 403

    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    hashed_password = hash_password(password)
    admin = db["accounts"].insert_one({
        "email": email,
        "password": hashed_password,
        "idEmployee": IdEmployee("admin"),
        "status": True,
        "selfGen": False,
        "isLoggedInForTheFirstTime": True,
        "SubRole": 'SUPER_ADMIN'
    }).inserted_id
    return jsonify({'message': 'Admin account created successfully'}), 201

@app.route("/register", methods=["POST"])
@jwt_required()
def register():
    data = request.get_json()
    current_user= get_jwt_identity()
    user = db["accounts"].find_one({"idEmployee": current_user})
    if user.get('Role') == 'SUPER_ADMIN':
        email = data.get('email')
        password = data.get('password')
        SubRole = data.get('SubRole')
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        hashed_password = hash_password(password)
        team_lead = db["accounts"].insert_one({
            "email": email,
            "password": hashed_password,
            "idEmployee": IdEmployee(team_lead), 
            "status": True,
            "selfGen": False,
            "isLoggedInForTheFirstTime": True,
            "SubRole": 'TEAM_LEAD',
            "access_token": create_token() 
        }).inserted_id
        return jsonify({'message': 'Team lead registered successfully', 'team_lead_id': team_lead})
    elif user.get('SubRole') == 'TEAM_LEAD':
        email = data.get('email')
        password = data.get('password')
        hashed_password = hash_password(password)
        SubRole = data.get('SubRole')
        employee_id = db["accounts"].insert_one({
            "email": email,
            "password": hashed_password,
            "idEmployee": IdEmployee("employee"),
            "status": True,
            "selfGen": False,
            "isLoggedInForTheFirstTime": True,
            "SubRole": 'employee',
            "IdResponsable": team_lead['idEmployee'] 
        }).inserted_id
        return jsonify({'message': 'Employee registered successfully', 'employee_id': employee_id}),200
    else:
        return jsonify({'error': 'Invalid subrole. Allowed subroles are TEAM_LEAD and SUPER_ADMIN '}), 400    
    

def IdEmployee(key):
    employee = db["accounts"].find()
    n=list(employee)
    x=len(n)+1
    if key == 'admin':
        return f'ADMIN_{x}'
    elif key == 'team_lead':
        return f'TEAM_LEAD_{x}'
    elif key == 'employee':
        return x 
    else:
         return jsonify({'error': 'Invalid key'}), 400  

def create_token(idEmployee):
    access_token = create_access_token(identity=idEmployee)
    return jsonify(access_token=access_token), 200

def get_current_user():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route('/get_employee_data', methods=['GET'])
@jwt_required()
def get():
    # Access the identity of the current user
    current_user_id = get_jwt_identity()
    user = db["accounts"].find_one({"idEmployee": current_user_id})
    if user:
        if 'SubRole' not in user:
            # Admin
            all_data = list(db["employees"].find())
            for data in all_data:
                for key, value in data.items():
                    if type(value) not in (int,bool, str): 
                        data[key] = str(value)

            return jsonify({"data": all_data})
        elif user.get('SubRole') == 'TEAM_LEAD':
            # Team lead
            team_data = get_team_data(user['idEmployee'])
            for data in team_data:
                for key, value in data.items():
                    if type(value) not in (int,bool, str) : 
                        data[key] = str(value)
            return jsonify(team_data)
        else:
            # Normal employee
            employee = get_employee_data(user['idEmployee'])
            for data in employee:
                for key, value in data.items():
                    if type(value) not in (int,bool, str): 
                        data[key] = str(value)
            if employee:
                return jsonify(employee)
            else:
                return jsonify({'error': 'Employee data not found'}), 404
    else:
        return jsonify({'error': 'Authentication failed'}), 401

@app.route('/updatedata', methods=['PUT', 'PATCH'])
@jwt_required()
def update_data(matricule):
    data = request.get_json()
    current_user = get_jwt_identity()
    user = db["employees"].find_one({"matricule": current_user})
    if matricule not in user:
        return jsonify({"error": "matricule not found"}), 404
    auth_matricule = request.headers.get('matricule')
    if auth_matricule != matricule:
        return jsonify({"error": "Unauthorized"}), 401 
    else:   
        updated_data = request.get_json() 
        user['matricule'].update(updated_data) 
    return jsonify({"message": "Employee data updated successfully"})
###################
@app.route('/update_password', methods=['PUT'])
@jwt_required()
def update_password():
    accounts=db["accounts"]
    data = request.get_json()
    if not data or 'password' not in data or 'new_password' not in data:
        return jsonify({"error": "Previous and new passwords are required"}), 400
    password = data.get('password')
    current_user = get_jwt_identity()
    user = db["employees"].find_one({"idEmployee": current_user, "password":password})
    new_password = data.get('new_password')
    hashed_new_password = hash_password(new_password)
    if user:
        # Check if the previous password matches the one stored in the database
        if check_password_hash(user['password'], password):
            # Update password with the new hashed password
            db["employees"].update_one({"idEmployee": current_user}, {"$set": {"password": hashed_new_password}})
            return jsonify({"message": "Password updated successfully"}), 200
        else:
            return jsonify({"error": "Previous password is incorrect"}), 400
    else:
        return jsonify({"error": "User not found"}), 404

###################
@ app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify(msg='Missing JSON in request'), 400
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'email et mot de passe requis'}), 400

    hashed_password = hash_password(password)
    accounts = db["accounts"]
    existing_accounts = accounts.find_one({'email': email, "password": hashed_password})

    if not existing_accounts:
        return jsonify({'error': 'email ou mot de passe incorrect'}), 404
    else:
        access_token = create_token(existing_accounts['idEmployee'])
        return access_token 


def authenticate_user(email, password):
    user = db["accounts"].find_one({'email': email, 'password': password})
    return user

def get_team_data(id):
    team_data = db["employees"].find({'$or': [{'matricule': id}, {'_idResponsable': id}]})
    return list(team_data)


def get_employee_data(id):
    team_data = db["employees"].find({'matricule': id})
    return list(team_data)


@app.route('/accounts/delete/<idEmployee>', methods=['DELETE'])
@jwt_required()
def delete_account(idEmployee):
    current_user = get_jwt_identity()
    user = db["accounts"].find_one({"idEmployee": current_user})
    if not user:
        return jsonify({'error": "Account not found'}), 404
    
    if user.get('Role') == 'SUPER_ADMIN':
        team_lead = db["accounts"].find_one({"idEmployee": idEmployee, "Role": "TEAM_LEAD"})
        if team_lead:
            # Admin can delete the team lead's account and all team members
            result = db["accounts"].delete_one({"idEmployee": idEmployee})
            # Delete team members (employees) of the deleted team lead
            db["accounts"].delete_many({"idResponsable": idEmployee})
            return jsonify({'message': 'Team lead account and team members deleted'}), 200
        else:
            return jsonify({"error": "The provided ID does not belong to a team lead"}), 400
    elif user.get('Role') == 'TEAM_LEAD':
        # Check if the current user is deleting own account or other team lead's account
        if idEmployee == current_user:
            result = db["accounts"].delete_one({"idEmployee": idEmployee})
            return jsonify({'message': 'Team lead account deleted'}), 200
        else:
            # User is a team lead but trying to delete another team lead
            return jsonify({'error': 'Unauthorized. Team lead can only delete own account.'}), 403

if __name__ == "__main__":
    app.run(port=80, debug=True)   
