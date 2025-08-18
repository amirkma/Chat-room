import gevent
gevent.monkey_patch()

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit, disconnect, join_room
import secrets
import hashlib
import threading
import time
import logging

# تنظیم لاگ برای دیباگ
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='gevent', logger=True, engineio_logger=True, ping_timeout=30, ping_interval=15)

# ساختار داده برای روم‌ها
rooms = {}  # {room_id: {'invite_code': str, 'users': {sid: {'username': str, 'role': str}}, 'chat_history': [], 'banned': set()}}
inactive_timers = {}
last_check_times = {}

def check_inactive_room(room_id):
    global inactive_timers, last_check_times
    logging.debug(f"Checking inactive room: {room_id}")
    if room_id not in rooms or len(rooms[room_id]['users']) == 0:
        current_time = time.time()
        if room_id in last_check_times and current_time - last_check_times[room_id] >= 60:
            if room_id in rooms:
                del rooms[room_id]
                logging.info(f"Room {room_id} inactive: Cleared.")
        else:
            inactive_timers[room_id] = threading.Timer(10, check_inactive_room, args=[room_id])
            inactive_timers[room_id].start()
    else:
        last_check_times[room_id] = time.time()
        inactive_timers[room_id] = threading.Timer(10, check_inactive_room, args=[room_id])
        inactive_timers[room_id].start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    invite_code = request.form['invite_code']
    
    room_id = None
    for rid, room in rooms.items():
        if room['invite_code'] == invite_code:
            room_id = rid
            break
    
    if room_id is None:
        logging.warning(f"Invalid invite code: {invite_code}")
        return render_template('index.html', error="Invalid invite code!")
    if username in rooms[room_id]['banned']:
        logging.warning(f"Banned user attempted to join: {username}")
        return render_template('index.html', error="You are banned!")
    
    session['username'] = username
    session['room_id'] = room_id
    session['role'] = 'Member'
    logging.info(f"User {username} logged in to room {room_id}")
    return redirect(url_for('chat'))

@app.route('/generate_code', methods=['POST'])
def generate_code():
    username = request.form.get('username')
    if not username:
        logging.warning("Generate code attempted without username")
        return jsonify({'error': 'Username is required!'})
    
    if len(rooms) >= 10:
        logging.warning("Maximum number of rooms reached")
        return jsonify({'error': 'Maximum number of rooms reached!'})
    
    room_id = secrets.token_hex(16)
    invite_code = generate_secure_code()
    
    rooms[room_id] = {
        'invite_code': invite_code,
        'users': {},
        'chat_history': [],
        'banned': set()
    }
    last_check_times[room_id] = time.time()
    
    with app.app_context():
        check_inactive_room(room_id)
    
    session['username'] = username
    session['room_id'] = room_id
    session['role'] = 'Owner'
    logging.info(f"New room created: {room_id} with invite code {invite_code} by {username}")
    return jsonify({'code': invite_code, 'redirect': url_for('chat')})

@app.route('/chat')
def chat():
    if 'username' not in session or 'room_id' not in session:
        logging.warning("Unauthorized access to /chat")
        return redirect(url_for('index'))
    room_id = session['room_id']
    role = session.get('role', 'Member')
    invite_code = rooms[room_id]['invite_code'] if room_id in rooms else ''
    logging.debug(f"Rendering chat for user {session['username']} in room {room_id}")
    return render_template('chat.html', username=session['username'], role=role, invite_code=invite_code if role == 'Owner' else '')

def generate_secure_code():
    random_bytes = secrets.token_bytes(32)
    hashed = hashlib.sha256(random_bytes).hexdigest()
    return hashed[:32]

@socketio.on('connect')
def connect(auth=None):
    username = session.get('username')
    room_id = session.get('room_id')
    
    if not username or not room_id or room_id not in rooms:
        logging.warning(f"Connect failed: username={username}, room_id={room_id}")
        disconnect()
        return
    
    join_room(room_id)
    role = session.get('role', 'Member')
    rooms[room_id]['users'][request.sid] = {'username': username, 'role': role}
    logging.info(f"User {username} connected to room {room_id} with SID {request.sid}")
    
    update_user_list(room_id)
    emit('message', {
        'id': secrets.token_hex(8),
        'username': 'System',
        'message': f'{username} ({role}) joined.',
        'timestamp': time.strftime('%H:%M:%S'),
        'type': 'join'
    }, room=room_id)
    for msg in rooms[room_id]['chat_history']:
        emit('message', msg, to=request.sid)

@socketio.on('disconnect')
def disconnect_handler():
    room_id = session.get('room_id')
    if room_id not in rooms:
        logging.warning(f"Disconnect: Room {room_id} not found")
        return
    
    user_data = rooms[room_id]['users'].pop(request.sid, None)
    if user_data:
        username = user_data['username']
        role = user_data['role']
        logging.info(f"User {username} disconnected from room {room_id}")
        if role == 'Owner':
            emit('message', {
                'id': secrets.token_hex(8),
                'username': 'System',
                'message': 'Room closed because Owner left.',
                'timestamp': time.strftime('%H:%M:%S'),
                'type': 'system'
            }, room=room_id)
            for sid in list(rooms[room_id]['users'].keys()):
                emit('room_closed', {'message': 'Room closed because Owner left.'}, to=sid)
                disconnect(sid)
            if room_id in inactive_timers:
                inactive_timers[room_id].cancel()
            del rooms[room_id]
            del last_check_times[room_id]
            logging.info(f"Room {room_id} closed: Owner disconnected.")
        else:
            update_user_list(room_id)
            msg = {
                'id': secrets.token_hex(8),
                'username': 'System',
                'message': f'{username} ({role}) left.',
                'timestamp': time.strftime('%H:%M:%S'),
                'type': 'leave'
            }
            rooms[room_id]['chat_history'].append(msg)
            emit('message', msg, room=room_id)

@socketio.on('message')
def handle_message(data):
    room_id = session.get('room_id')
    if room_id not in rooms:
        logging.warning(f"Message: Room {room_id} not found")
        return
    
    user_data = rooms[room_id]['users'].get(request.sid)
    if not user_data:
        logging.warning(f"Message: User not found for SID {request.sid}")
        return
    
    username = user_data['username']
    role = user_data['role']
    message = data['message']
    reply_to = data.get('reply_to', None)
    logging.debug(f"Message from {username} in room {room_id}: {message}, reply_to: {reply_to}")
    
    if role == 'Owner' and message.startswith('/'):
        command = message[1:].split()
        if command[0] == 'kick' and len(command) > 1:
            target = command[1]
            for sid, user in list(rooms[room_id]['users'].items()):
                if user['username'] == target:
                    emit('kick', {'message': 'You have been kicked!'}, to=sid)
                    disconnect(sid)
                    msg = {
                        'id': secrets.token_hex(8),
                        'username': 'System',
                        'message': f'{target} was kicked.',
                        'timestamp': time.strftime('%H:%M:%S'),
                        'type': 'system'
                    }
                    rooms[room_id]['chat_history'].append(msg)
                    emit('message', msg, room=room_id)
                    update_user_list(room_id)
                    return
        elif command[0] == 'ban' and len(command) > 1:
            target = command[1]
            rooms[room_id]['banned'].add(target)
            for sid, user in list(rooms[room_id]['users'].items()):
                if user['username'] == target:
                    emit('ban', {'message': 'You have been banned!'}, to=sid)
                    disconnect(sid)
            msg = {
                'id': secrets.token_hex(8),
                'username': 'System',
                'message': f'{target} was banned.',
                'timestamp': time.strftime('%H:%M:%S'),
                'type': 'system'
            }
            rooms[room_id]['chat_history'].append(msg)
            emit('message', msg, room=room_id)
            update_user_list(room_id)
            return
        elif command[0] == 'close':
            emit('message', {
                'id': secrets.token_hex(8),
                'username': 'System',
                'message': 'Room closed by Owner.',
                'timestamp': time.strftime('%H:%M:%S'),
                'type': 'system'
            }, room=room_id)
            for sid in list(rooms[room_id]['users'].keys()):
                emit('room_closed', {'message': 'Room closed by Owner.'}, to=sid)
                disconnect(sid)
            if room_id in inactive_timers:
                inactive_timers[room_id].cancel()
            del rooms[room_id]
            del last_check_times[room_id]
            logging.info(f"Room {room_id} closed: Closed by Owner.")
            return
    
    msg_data = {
        'id': secrets.token_hex(8),
        'username': username,
        'role': role,
        'message': message,
        'timestamp': time.strftime('%H:%M:%S'),
        'type': 'user',
        'reply_to': reply_to
    }
    rooms[room_id]['chat_history'].append(msg_data)
    if len(rooms[room_id]['chat_history']) > 100:
        rooms[room_id]['chat_history'] = rooms[room_id]['chat_history'][-100:]
    emit('message', msg_data, room=room_id)

def update_user_list(room_id):
    if room_id in rooms:
        user_list = [{'username': user['username'], 'role': user['role']} for user in rooms[room_id]['users'].values()]
        logging.debug(f"Updating user list for room {room_id}: {user_list}")
        emit('user_list', {'users': user_list}, room=room_id)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)
