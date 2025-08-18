import eventlet
eventlet.monkey_patch()  # باید قبل از هر import دیگری باشه

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit, disconnect
import secrets
import hashlib
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='eventlet')

# ساختار داده برای روم‌ها
rooms = {}  # {room_id: {'invite_code': str, 'users': {sid: {'username': str, 'role': str}}, 'chat_history': [], 'banned': set()}}
inactive_timers = {}  # {room_id: timer}
last_check_times = {}  # {room_id: last_check_time}

# تابع بررسی روم غیرفعال
def check_inactive_room(room_id):
    global inactive_timers, last_check_times
    if room_id not in rooms or len(rooms[room_id]['users']) == 0:
        current_time = time.time()
        if room_id in last_check_times and current_time - last_check_times[room_id] >= 60:  # 1 minute
            if room_id in rooms:
                del rooms[room_id]
                print(f"Room {room_id} inactive: Cleared.")
        else:
            inactive_timers[room_id] = threading.Timer(10, check_inactive_room, args=[room_id])
            inactive_timers[room_id].start()
    else:
        last_check_times[room_id] = time.time()
        inactive_timers[room_id] = threading.Timer(10, check_inactive_room, args=[room_id])
        inactive_timers[room_id].start()

# Main page (login)
@app.route('/')
def index():
    return render_template('index.html')

# Handle login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    invite_code = request.form['invite_code']
    
    # پیدا کردن room_id مرتبط با invite_code
    room_id = None
    for rid, room in rooms.items():
        if room['invite_code'] == invite_code:
            room_id = rid
            break
    
    if room_id is None:
        return render_template('index.html', error="Invalid invite code!")
    if username in rooms[room_id]['banned']:
        return render_template('index.html', error="You are banned!")
    
    session['username'] = username
    session['room_id'] = room_id
    session['role'] = 'Member'  # Default for joiners
    return redirect(url_for('chat'))

# Generate new code (AJAX)
@app.route('/generate_code', methods=['POST'])
def generate_code():
    username = request.form.get('username')
    if not username:
        return jsonify({'error': 'Username is required!'})
    
    # تولید Room ID و Invite Code جدید
    room_id = secrets.token_hex(16)  # Room ID منحصربه‌فرد
    invite_code = generate_secure_code()
    
    # اضافه کردن روم جدید
    rooms[room_id] = {
        'invite_code': invite_code,
        'users': {},
        'chat_history': [],
        'banned': set()
    }
    last_check_times[room_id] = time.time()
    
    # شروع تایمر برای بررسی غیرفعال بودن روم
    with app.app_context():
        check_inactive_room(room_id)
    
    session['username'] = username
    session['room_id'] = room_id
    session['role'] = 'Owner'
    return jsonify({'code': invite_code, 'redirect': url_for('chat')})

# Chat page
@app.route('/chat')
def chat():
    if 'username' not in session or 'room_id' not in session:
        return redirect(url_for('index'))
    room_id = session['room_id']
    role = session.get('role', 'Member')
    invite_code = rooms[room_id]['invite_code'] if room_id in rooms else ''
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
    room_id = session.get('room_id')
    
    if username and room_id in rooms and rooms[room_id]['invite_code']:
        role = session.get('role', 'Member')
        rooms[room_id]['users'][request.sid] = {'username': username, 'role': role}
        update_user_list(room_id)
        emit('message', {'username': 'System', 'message': f'{username} ({role}) joined.', 'timestamp': time.strftime('%H:%M:%S')}, room=room_id)
        for msg in rooms[room_id]['chat_history']:
            emit('message', msg)

# When user disconnects
@socketio.on('disconnect')
def disconnect_handler():
    room_id = session.get('room_id')
    if room_id not in rooms:
        return
    
    user_data = rooms[room_id]['users'].pop(request.sid, None)
    if user_data:
        username = user_data['username']
        role = user_data['role']
        if role == 'Owner':
            emit('message', {'username': 'System', 'message': 'Room closed because Owner left.', 'timestamp': time.strftime('%H:%M:%S')}, room=room_id)
            for sid in list(rooms[room_id]['users'].keys()):
                emit('room_closed', {'message': 'Room closed because Owner left.'}, to=sid)
                disconnect(sid)
            if room_id in inactive_timers:
                inactive_timers[room_id].cancel()
            del rooms[room_id]
            del last_check_times[room_id]
            print(f"Room {room_id} closed: Owner disconnected.")
        else:
            update_user_list(room_id)
            msg = f'{username} ({role}) left.'
            rooms[room_id]['chat_history'].append({'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')})
            emit('message', {'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')}, room=room_id)

# Handle messages
@socketio.on('message')
def handle_message(data):
    room_id = session.get('room_id')
    if room_id not in rooms:
        return
    
    user_data = rooms[room_id]['users'].get(request.sid)
    if not user_data:
        return
    
    username = user_data['username']
    role = user_data['role']
    message = data['message']
    
    if role == 'Owner' and message.startswith('/'):
        command = message[1:].split()
        if command[0] == 'kick' and len(command) > 1:
            target = command[1]
            for sid, user in list(rooms[room_id]['users'].items()):
                if user['username'] == target:
                    emit('kick', {'message': 'You have been kicked!'}, to=sid)
                    disconnect(sid)
                    msg = f'{target} was kicked.'
                    rooms[room_id]['chat_history'].append({'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')})
                    emit('message', {'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')}, room=room_id)
                    update_user_list(room_id)
                    return
        elif command[0] == 'ban' and len(command) > 1:
            target = command[1]
            rooms[room_id]['banned'].add(target)
            for sid, user in list(rooms[room_id]['users'].items()):
                if user['username'] == target:
                    emit('ban', {'message': 'You have been banned!'}, to=sid)
                    disconnect(sid)
            msg = f'{target} was banned.'
            rooms[room_id]['chat_history'].append({'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')})
            emit('message', {'username': 'System', 'message': msg, 'timestamp': time.strftime('%H:%M:%S')}, room=room_id)
            update_user_list(room_id)
            return
        elif command[0] == 'close':
            emit('message', {'username': 'System', 'message': 'Room closed by Owner.', 'timestamp': time.strftime('%H:%M:%S')}, room=room_id)
            for sid in list(rooms[room_id]['users'].keys()):
                emit('room_closed', {'message': 'Room closed by Owner.'}, to=sid)
                disconnect(sid)
            if room_id in inactive_timers:
                inactive_timers[room_id].cancel()
            del rooms[room_id]
            del last_check_times[room_id]
            print(f"Room {room_id} closed: Closed by Owner.")
            return
    
    msg_data = {'username': username, 'role': role, 'message': message, 'timestamp': time.strftime('%H:%M:%S')}
    rooms[room_id]['chat_history'].append(msg_data)
    emit('message', msg_data, room=room_id)

# Update user list
def update_user_list(room_id):
    if room_id in rooms:
        user_list = [{'username': user['username'], 'role': user['role']} for user in rooms[room_id]['users'].values()]
        emit('user_list', {'users': user_list}, room=room_id)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)
