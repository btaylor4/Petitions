# server.py
from __future__ import absolute_import, print_function
from flask import Flask, render_template, redirect, url_for, request, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
from flask_socketio import SocketIO
from flask_socketio import send, emit
from bson import json_util, ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from pprint import pprint
import unittest
import webbrowser
import docusign_esign as docusign
from docusign_esign import AuthenticationApi, TemplatesApi, EnvelopesApi
from docusign_esign.rest import ApiException

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

    elif(message['type'] == 'sendDocument'):
        user_name = "60d34380-6d41-4fa8-9701-05490acea776"
        integrator_key = "fe7f0a39-3572-4979-9fa7-79f38d969132"
        base_url = "https://demo.docusign.net/restapi"
        oauth_base_url = "account-d.docusign.com" # use account.docusign.com for Live/Production
        redirect_uri = "https://www.docusign.com/api"
        private_key_filename = "keys/docusign_private_key.txt"
        user_id = "60d34380-6d41-4fa8-9701-05490acea776"
        template_id = "e82be205-2edb-46da-98e6-e9c20417b474"

        api_client = docusign.ApiClient(base_url)

        # IMPORTANT NOTE:
        # the first time you ask for a JWT access token, you should grant access by making the following call
        # get DocuSign OAuth authorization url:

        # oauth_login_url = api_client.get_jwt_uri(integrator_key, redirect_uri, oauth_base_url)

        # open DocuSign OAuth authorization url in the browser, login and grant access
        # webbrowser.open_new_tab(oauth_login_url)
        # END OF NOTE

        # configure the ApiClient to asynchronously get an access token and store it
        api_client.configure_jwt_authorization_flow(private_key_filename, oauth_base_url, integrator_key, user_id, 3600)

        docusign.configuration.api_client = api_client

        template_role_name = 'test'

        # create an envelope to be signed
        envelope_definition = docusign.EnvelopeDefinition()
        envelope_definition.email_subject = 'Please Sign my Python SDK Envelope'
        envelope_definition.email_blurb = 'Hello, Please sign my Python SDK Envelope.'

        # assign template information including ID and role(s)
        envelope_definition.template_id = 'e82be205-2edb-46da-98e6-e9c20417b474'

        # create a template role with a valid template_id and role_name and assign signer info
        t_role = docusign.TemplateRole()
        t_role.role_name = 'test'
        t_role.name ='Signer'
        t_role.email = 'clearly.b.t@gmail.com'

        # create a list of template roles and add our newly created role
        # assign template role(s) to the envelope
        envelope_definition.template_roles = [t_role]

        # send the envelope by setting |status| to "sent". To save as a draft set to "created"
        envelope_definition.status = 'sent'

        auth_api = AuthenticationApi()
        envelopes_api = EnvelopesApi()

        try:
            login_info = auth_api.login(api_password='true', include_account_id_guid='true')
            assert login_info is not None
            assert len(login_info.login_accounts) > 0
            login_accounts = login_info.login_accounts
            assert login_accounts[0].account_id is not None

            base_url, _ = login_accounts[0].base_url.split('/v2')
            api_client.host = base_url
            docusign.configuration.api_client = api_client

            envelope_summary = envelopes_api.create_envelope(login_accounts[0].account_id, envelope_definition=envelope_definition)
            assert envelope_summary is not None
            assert envelope_summary.envelope_id is not None
            assert envelope_summary.status == 'sent'

            print("EnvelopeSummary: ", end="")
            pprint(envelope_summary)

        except ApiException as e:
            print("\nException when calling DocuSign API: %s" % e)
            assert e is None # make the test case fail in case of an API exception

@app.route('/start-petition', methods=['GET', 'POST']) # sets up the page for registration
def start_petition():
    return render_template('start_petition.html')  

@app.route('/dashboard', methods=['GET', 'POST']) # sets up the page for registration
def dashboard():
    return render_template('dashboard.html')  

@app.route('/logout')
def logout():
    session.pop('username', None)
    return render_template("index.html")

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    socketio.run(app, debug=True) # debug = true to put in debug mode