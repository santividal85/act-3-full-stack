from flask import Flask, request, jsonify
import json
import bcrypt
import jwt
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_secreta'

# ========= HELPERS =========
def read_json(file):
    try:
        with open(file, 'r') as f:
            return json.load(f)
    except:
        return []

def write_json(file, data):
    with open(file, 'w') as f:
        json.dump(data, f, indent=2)

# ========= AUTH =========
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth:
            return jsonify({'error': 'Token requerido'}), 401
        try:
            token = auth.split(' ')[1]
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'error': 'Token inválido'}), 403
        return f(*args, **kwargs)
    return decorated

# ========= REGISTER =========
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    users = read_json('users.json')

    password = bcrypt.hashpw(
        data['password'].encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    users.append({
        'id': len(users) + 1,
        'email': data['email'],
        'password': password
    })

    write_json('users.json', users)
    return jsonify({'message': 'Usuario registrado'}), 201

# ========= LOGIN =========
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    users = read_json('users.json')

    user = next((u for u in users if u['email'] == data['email']), None)
    if not user or not bcrypt.checkpw(
        data['password'].encode('utf-8'),
        user['password'].encode('utf-8')
    ):
        return jsonify({'error': 'Credenciales incorrectas'}), 401

    token = jwt.encode({
        'id': user['id'],
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token})

# ========= TAREAS =========
@app.route('/tareas', methods=['GET'])
@token_required
def get_tareas():
    return jsonify(read_json('tareas.json'))

@app.route('/tareas', methods=['POST'])
@token_required
def create_tarea():
    data = request.json
    tareas = read_json('tareas.json')

    tarea = {
        'id': len(tareas) + 1,
        'titulo': data['titulo'],
        'descripcion': data['descripcion']
    }

    tareas.append(tarea)
    write_json('tareas.json', tareas)
    return jsonify(tarea), 201

@app.route('/tareas/<int:id>', methods=['PUT'])
@token_required
def update_tarea(id):
    tareas = read_json('tareas.json')
    tarea = next((t for t in tareas if t['id'] == id), None)

    if not tarea:
        return jsonify({'error': 'Tarea no encontrada'}), 404

    tarea['titulo'] = request.json['titulo']
    tarea['descripcion'] = request.json['descripcion']
    write_json('tareas.json', tareas)
    return jsonify(tarea)

@app.route('/tareas/<int:id>', methods=['DELETE'])
@token_required
def delete_tarea(id):
    tareas = read_json('tareas.json')
    tareas = [t for t in tareas if t['id'] != id]
    write_json('tareas.json', tareas)
    return jsonify({'message': 'Tarea eliminada'})

# ========= ERRORES =========
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Ruta no encontrada'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Error del servidor'}), 500

# ========= RUN =========
if __name__ == '__main__':
    app.run(debug=True)