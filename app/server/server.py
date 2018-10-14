# server.py
from flask import Flask, render_template, redirect, url_for, request, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
from flask_socketio import SocketIO
from flask_socketio import send, emit
from bson import json_util, ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json

app = Flask(__name__, static_folder="../static", template_folder="../static")
app.config['MONGO_DBNAME'] = "sdhacks"
app.config['MONGO_URI'] = "mongodb://hacker:sleepingbag1@ds131763.mlab.com:31763/sdhacks"
app.secret_key = os.urandom(24)
socketio = SocketIO(app)
mongo = PyMongo(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

connectedUsers = {}

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"username": user_id})
    if not user:
        return None
    return User(user['_id'])

class User():
    def __init__(self, username):
        self.username = username
        self.email = None

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.username

def sendToRoom(connection, message):
    connection.send(message, room=message["room"])

@app.route('/new-customer', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # construct user
        # name = request.form['firstname']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        requested_user = mongo.db.users.find_one({'username': username}) # searches the data base for the username chosen
        if requested_user is None:
            mongo.db.users.insert({'username': username, 'password': hashed_password}) # makes a new user inside data base if non already exits
            return redirect(url_for('index')) # send back to landing page
    
        else:
            return 'Username has already been taken'
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST']) # sets up the page for registration
def login():
    if request.method == 'POST':
        requested_user = mongo.db.users.find_one({'username': request.form['username']})
        if requested_user:
            if check_password_hash(requested_user["password"], request.form['password']):
                connectedUsers[request.form['username']] = None
                user = User(username=request.form['username'])
                login_user(user)
                return redirect(url_for('dashboard')) # send to page with video functionality
        return 'Invalid Credentials. Please try again.'
    return render_template('login.html')

@socketio.on('message')
def handle_message(message): # server has recieved a message from a client
    print(message)
    if(message['type'] == 'coordinates'):
        petitions = mongo.db.petitions.find_one({'username': message['username']})

        petition = {
                'petition_name': message['petition_name'],
                'petition_decr': message['petition_name'] ,
                'lng': message['lng'],
                'lat': message['lat']
        }

        if petitions:
            p_list = list(petitions['petitions'])
            p_list.append(petition)
            mongo.db.users.update_one(
                { "username" : message["username"]},
                { "$set": 
                    {
                        "petitions": p_list
                    } 
                }
            )

        else:
            p_list = list()
            p_list.append(petition)
            print(p_list)
            mongo.db.petitions.insert_one(
                { "username" : message["username"]},
                { "petitions": [] } 
            )

            mongo.db.petitions.update_one(
                { "username" : message["username"]},
                { "$set": 
                    {
                        "petitions": p_list
                    }
                }
            )

    elif(message['type'] == 'getPetitions'):
        room = connectedUsers[message["username"]]

        all_p = mongo.db.petitions.find()
        p_list = list()
        for message in all_p:
            for petitions in list(message['petitions']):
                p_list.append(petitions)

        sendToRoom(socketio, {
            "type": "gotPetitions", 
            "petitions": json.loads(json_util.dumps(p_list)),
            "room": room
        })

@app.route('/start-petition', methods=['GET', 'POST']) # sets up the page for registration
def start_petition():
    return render_template('start_petition.html')  

@app.route('/dashboard', methods=['GET', 'POST']) # sets up the page for registration
def dashboard():
    return render_template('dashboard.html')  

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    socketio.run(app, debug=True) # debug = true to put in debug mode