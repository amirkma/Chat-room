from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, join_room, emit
import secrets
import logging
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Store rooms and banned users
rooms = {}
banned_users = {}

def generate_room_code():
    return secrets.token_hex(16)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_room', methods=['POST'])
def create_room():
    username = request.form.get('username')
    if not username:
        return redirect(url_for('index'))
    
    room_id = generate_room_code()
    session['room_id'] = room_id
    session['username'] = username
    session['role'] = 'Owner'
    
    rooms[room_id] = {
        'users': {username: {'sid': None, 'role': 'Owner'}},
        'chat_history': []
    }
    
    logging.debug(f"Room created: {room_id} by {username}")
    return redirect(url_for('chat', invite_code=room_id))

@app.route('/join_room', methods=['POST'])
def join_room():
    username = request.form.get('username')
    invite_code = request.form.get('invite_code')
    
    if not username or not invite_code:
        return redirect(url_for('index'))
    
    if invite_code in rooms:
        if username in banned_users.get(invite_code, []):
            return render_template('index.html', error="You are banned from this room.")
        session['room_id'] = invite_code
        session['username'] = username
        session['role'] = 'Member'
        rooms[invite_code]['users'][username] = {'sid': None, 'role': 'Member'}
        logging.debug(f"User {username} joined room {invite_code}")
        return redirect(url_for('chat', invite_code=invite_code))
    else:
        return render_template('index.html', error="Invalid room code.")

@app.route('/chat/<invite_code>')
def chat(invite_code):
    if 'username' not in session or 'room_id' not in session:
        return redirect(url_for('index'))
    
    if invite_code != session['room_id']:
        return redirect(url_for('index'))
    
    return render_template('chat.html', 
                         username=session['username'], 
                         role=session['role'], 
                         invite_code=invite_code)

@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    username = data.get('username')
    role = data.get('role')
    
    if room_id not in rooms:
        logging.error(f"Room {room_id} does not exist")
        return
    
    join_room(room_id)
    rooms[room_id]['users'][username]['sid'] = request.sid
    logging.debug(f"User {username} connected to room {room_id} with SID {request.sid}")
    
    emit('message', {
        'message': f'{username} ({role}) joined.',
        'role': 'System',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': 'join'
    }, room=room_id)
    
    emit('user_list', {'users': [{'username': u, 'role': r['role']} for u, r in rooms[room_id]['users'].items()]}, room=room_id)

@socketio.on('message')
def handle_message(data):
    room_id = data.get('room_id')
    message = data.get('message')
    reply_to = data.get('reply_to')
    
    if not room_id or room_id not in rooms:
        logging.error(f"Invalid room_id: {room_id}")
        return
    
    username = session.get('username')
    role = session.get('role')
    
    if not username or not role:
        logging.error("No username or role in session")
        return
    
    logging.debug(f"Message from {username} in room {room_id}: {message}, reply_to: {reply_to}")
    
    if message.startswith('/kick ') and role == 'Owner':
        target_username = message[6:].strip()
        if target_username in rooms[room_id]['users'] and rooms[room_id]['users'][target_username]['role'] != 'Owner':
            sid = rooms[room_id]['users'][target_username]['sid']
            if sid:
                emit('kick', {'message': f'You were kicked by {username}'}, to=sid)
            del rooms[room_id]['users'][target_username]
            emit('message', {
                'message': f'{target_username} was kicked by {username}.',
                'role': 'System',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'kick'
            }, room=room_id)
            emit('user_list', {'users': [{'username': u, 'role': r['role']} for u, r in rooms[room_id]['users'].items()]}, room=room_id)
        return
    
    if message.startswith('/ban ') and role == 'Owner':
        target_username = message[5:].strip()
        if target_username in rooms[room_id]['users'] and rooms[room_id]['users'][target_username]['role'] != 'Owner':
            sid = rooms[room_id]['users'][target_username]['sid']
            if sid:
                emit('ban', {'message': f'You were banned by {username}'}, to=sid)
            del rooms[room_id]['users'][target_username]
            if room_id not in banned_users:
                banned_users[room_id] = []
            banned_users[room_id].append(target_username)
            emit('message', {
                'message': f'{target_username} was banned by {username}.',
                'role': 'System',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'ban'
            }, room=room_id)
            emit('user_list', {'users': [{'username': u, 'role': r['role']} for u, r in rooms[room_id]['users'].items()]}, room=room_id)
        return
    
    message_id = secrets.token_hex(8)
    message_data = {
        'id': message_id,
        'message': message,
        'username': username,
        'role': role,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'reply_to': reply_to
    }
    
    rooms[room_id]['chat_history'].append(message_data)
    emit('message', message_data, room=room_id)

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    room_id = session.get('room_id')
    
    if not username or not room_id or room_id not in rooms:
        logging.debug(f"Disconnect: No valid session or room for {username}, {room_id}")
        return
    
    logging.debug(f"User {username} disconnected from room {room_id}")
    
    if username in rooms[room_id]['users']:
        role = rooms[room_id]['users'][username]['role']
        del rooms[room_id]['users'][username]
        
        if role == 'Owner':
            # Close the room if the owner disconnects
            emit('room_closed', {
                'message': 'Room closed by Owner.',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }, room=room_id)
            del rooms[room_id]
            if room_id in banned_users:
                del banned_users[room_id]
            logging.debug(f"Room {room_id} closed because Owner {username} disconnected")
        else:
            # Notify others of member leaving
            emit('message', {
                'message': f'{username} ({role}) left.',
                'role': 'System',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'leave'
            }, room=room_id)
            emit('user_list', {'users': [{'username': u, 'role': r['role']} for u, r in rooms[room_id]['users'].items()]}, room=room_id)

if __name__ == '__main__':
    socketio.run(app, debug=True)
