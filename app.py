from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit, disconnect
import secrets
import hashlib
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Invite codes, users, banned users, and chat history
INVITE_CODES = set(['initial_code'])  # Initial code for testing
users = {}  # {sid: {'username': str, 'role': str}}
banned = set()
chat_history = []

# Timer for checking inactive room
inactive_timer = None
last_check_time = time.time()

# Check for inactive room
def check_inactive_room():
    global inactive_timer, last_check_time
    if len(users) == 0:
        current_time = time.time()
        if current_time - last_check_time >= 60:  # 1 minute
            INVITE_CODES.clear()
            chat_history.clear()
            INVITE_CODES.add('initial_code')
            print("Room inactive: Invite codes and chat history cleared.")
        else:
            inactive_timer = threading.Timer(10, check_inactive_room)
            inactive_timer.start()
    else:
        last_check_time = time.time()
        inactive_timer = threading.Timer(10, check_inactive_room)
        inactive_timer.start()

# Start initial timer
check_inactive_room()

# Main page (login)
@app.route('/')
def index():
    return render_template('index.html')

# Handle login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    invite_code = request.form['invite_code']
    
    if invite_code not in INVITE_CODES:
        return render_template('index.html', error="Invalid invite code!")
    if username in banned:
        return render_template('index.html', error="You are banned!")
    
    session['username'] = username
    session['invite_code'] = invite_code
    session['role'] = 'Member'  # Default for joiners
    return redirect(url_for('chat'))

# Generate new code (AJAX)
@app.route('/generate_code', methods=['POST'])
def generate_code():
    username = request.form.get('username')
    if not username:
        return jsonify({'error': 'Username is required!'})
    new_code = generate_secure_code()
    INVITE_CODES.add(new_code)
    session['username'] = username
    session['invite_code'] = new_code
    session['role'] = 'Owner'
    return jsonify({'code': new_code, 'redirect': url_for('chat')})

# Chat page
@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('index'))
    role = session.get('role', 'Member')
    invite_code = session.get('invite_code', '')
    return render_template('chat.html', username=session['username'], role=role, invite_code=invite_code if role == 'Owner' else '')

# Generate secure invite code
def generate_secure_code():
    random_bytes = secrets.token_bytes(32)
    hashed = hashlib.sha256(random_bytes).hexdigest()
    return hashed[:32]  # 32-character hex

# When user connects
@socketio.on('connect')
def connect(auth=None):
    username = session.get('username')
    invite_code = session.get('invite_code')
    if username and invite_code in INVITE_CODES:
        role = session.get('role', 'Member')
        users[request.sid] = {'username': username, 'role': role}
        update_user_list()
        emit('message', {'username': 'System', 'message': f'{username} ({role}) joined.', 'timestamp': time.strftime('%H:%M:%S')}, broadcast=True)
        for msg in chat_history:
            emit('message', msg)

# When user disconnects
@socketio.on('disconnect')
def disconnect_handler():
    user_data = users.pop(request.sid, None)
    if user_data:
        username = user_data['username']
        role = user_data['role']
        if role == 'Owner':
            INVITE_CODES.clear()
            chat_history.clear()
            INVITE_CODES.add('initial_code')
            emit('message', {'username': 'System', 'message': 'Room closed because Owner left.', 'timestamp': time.strftime('%H:%M:%S')}, broadcast=True)
            for sid in list(users.keys()):
                emit('room_closed', {'message': 'Room closed because Owner left.'}, to=sid)
                disconnect(sid)
            print("Room closed: Owner disconnected.")
        else:
            update_user_list()
            msg = f'{username} ({role}) left.'
            chat_history.append({'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')})
            emit('message', {'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')}, broadcast=True)

# Handle messages
@socketio.on('message')
def handle_message(data):
    user_data = users.get(request.sid)
    if not user_data:
        return
    username = user_data['username']
    role = user_data['role']
    message = data['message']
    
    if role == 'Owner' and message.startswith('/'):
        command = message[1:].split()
        if command[0] == 'kick' and len(command) > 1:
            target = command[1]
            for sid, user in list(users.items()):
                if user['username'] == target:
                    emit('kick', {'message': 'You have been kicked!'}, to=sid)
                    disconnect(sid)
                    msg = f'{target} was kicked.'
                    chat_history.append({'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')})
                    emit('message', {'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')}, broadcast=True)
                    update_user_list()
                    return
        elif command[0] == 'ban' and len(command) > 1:
            target = command[1]
            banned.add(target)
            for sid, user in list(users.items()):
                if user['username'] == target:
                    emit('ban', {'message': 'You have been banned!'}, to=sid)
                    disconnect(sid)
            msg = f'{target} was banned.'
            chat_history.append({'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')})
            emit('message', {'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')}, broadcast=True)
            update_user_list()
            return
        elif command[0] == 'close':
            INVITE_CODES.clear()
            chat_history.clear()
            for sid in list(users.keys()):
                emit('room_closed', {'message': 'Room closed by Owner.'}, to=sid)
                disconnect(sid)
            INVITE_CODES.add('initial_code')
            print("Room closed: Invite codes and chat history cleared.")
            return
    
    msg_data = {'username': username, 'role': role, 'message': message, 'timestamp': time.strftime('%H:%M:%S')}
    chat_history.append(msg_data)
    emit('message', msg_data, broadcast=True)

# Update user list
def update_user_list():
    user_list = [{'username': user['username'], 'role': user['role']} for user in users.values()]
    emit('user_list', {'users': user_list}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)