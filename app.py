from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Welcome to the API', 'status': 'success'})

@app.route('/data', methods=['GET'])
def get_data():
    data = {'id': 1, 'name': 'example', 'value': 100}
    return jsonify({'data': data, 'status': 'success'})

@app.route('/data', methods=['POST'])
def post_data():
    try:
        content = request.get_json()
        if not content:
            return jsonify({'error': 'No JSON data provided', 'status': 'error'}), 400
        return jsonify({'received': content, 'status': 'success'}), 201
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 400

@app.route('/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    if user_id <= 0:
        return jsonify({'error': 'Invalid user ID', 'status': 'error'}), 400
    return jsonify({'user_id': user_id, 'name': f'User {user_id}', 'status': 'success'})

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found', 'status': 'error'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed', 'status': 'error'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'status': 'error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
