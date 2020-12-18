import os
import sys

from flask import Flask
from flask import jsonify
from flask import make_response
from flask import render_template
from flask import request
from flask import session
from flask import redirect
from random import randint
import util
from jwkest import BadSignature
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS
from models import Request
from context import webauthn
from models import User
from models import Credential
from database import Database
import yaml
import json
import time
import urllib
from flask_login import LoginManager
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user
from flask_login import current_user
from flask_reverse_proxy_fix.middleware import ReverseProxyPrefixFix

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for Flask application")
app.secret_key = SECRET_KEY

login_manager = LoginManager()
login_manager.init_app(app)

with open("/var/webauthn-module/py_webauthn/app/config.yaml", "r") as ymlfile:
    cfg = yaml.load(ymlfile)

database = Database(cfg)

RP_ID = cfg['host']['rp-id']
RP_NAME = 'webauthn'
ORIGIN = cfg['host']['origin']

if 'reverse_proxy_path' in cfg:
    app.config['REVERSE_PROXY_PATH'] = cfg['reverse_proxy_path']
    ReverseProxyPrefixFix(app)

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PREFERRED_URL_SCHEME'] = 'https'

TRUST_ANCHOR_DIR = 'trusted_attestation_roots'
public_key = RSAKey(key=rsa_load(cfg['caller']['public-key']), use="sig", alg="RS256")


@login_manager.user_loader
def load_user(user_id):
    '''
    The function that loads the user and returns them if they exist, returns None if the user does not exist
    '''
    user = database.get_user(user_id)
    if not user:
        return None
    user.id = user_id
    return user


@app.route('/credentials')
def credentials_manager():
    '''
    If the user is logged in, this url path returns the token management page
    '''
    if current_user.is_authenticated:
        username = current_user.id
        credentials_array = database.get_credentials(username)
        is_turned_off = database.is_turned_off(username)
        return render_template("credentials.html", credentials=credentials_array, username1=username, url=ORIGIN,
                               turn_off=cfg['host']['turn-off'], timeout=int(cfg['host']['turn-off-timeout-seconds']),
                               is_off=is_turned_off)
    return "User not logged in."


@app.route('/delete/<cred_id>', methods=['POST'])
def credentials_delete(cred_id):
    '''
    This url path is called when the user
     intends to delete one of their tokens, the
      user must be logged in and at least one
       token must be still registered
    '''
    if current_user.is_authenticated and len(database.get_credentials(current_user.id)) > 1:
        database.delete_credential(cred_id)
        return "success"
    return "failure"


@app.route('/authentication_request/<message>/')
def authentication_request_get(message):
    '''
    This is the url that other system uses to redirect the user in order to authenticate them
    '''
    try:
        message = JWS().verify_compact(message, keys=[public_key])
    except BadSignature:
        return "Signature invalid"
    # todo check whether signed correctly raise BadSignature
    satosa_request = Request(message)
    user = database.get_user(satosa_request.userId)
    if not database.request_exists(satosa_request):
        database.save_request(satosa_request)
    else:
        return "REPLAY ATTACK"
    
    api_url = cfg['caller']['callback-url'] + "?" + urllib.parse.urlencode({"StateId": satosa_request.nonce})
    if not user:
        database.save_user(satosa_request.userId)
        new_user = database.get_user(satosa_request.userId)
        login_user(new_user)
        return render_template('satosa_registration_index.html', username1=satosa_request.userId,
                               redirect_url1=api_url)
    if len(database.get_credentials(satosa_request.userId)) == 0:
        new_user = database.get_user(satosa_request.userId)
        login_user(new_user)
        return render_template('satosa_registration_index.html', username1=satosa_request.userId,
                               redirect_url1=api_url)

    if cfg['host']['turn-off'] and database.is_turned_off(user.id):
        database.turn_on(user.id)
        login_user(user)
        satosa_request = Request()
        satosa_request.userId = user.id
        database.make_success(satosa_request)
        username = current_user.id
        credentials_array = database.get_credentials(username)
        return render_template("credentials.html", credentials=credentials_array, username1=username, url=ORIGIN,
                               turn_off=cfg['host']['turn-off'], timeout=int(cfg['host']['turn-off-timeout-seconds']))
    return render_template('satosa_index.html', username1=satosa_request.userId,
                           redirect_url1=api_url)


@app.route('/request/<message>')
def get_request_with_key(message):
    '''
    This url path is called after authentication took place to check the result of it
    '''
    message = JWS().verify_compact(message, keys=[public_key])
    satosa_request = Request(message)
    request = database.get_request(satosa_request.nonce)
    response = ""
    if not request or request.userId != satosa_request.userId or request.success == 0 or int(request.time) + 300 < int(
            satosa_request.time):
        response = cfg['responses']['failure']
    elif request.success == 1:
        database.make_invalid(request)
        response = cfg['responses']['success']
    elif request.success == 2:
        response = cfg['responses']['invalid-request']
    else:
        response = "error"
    response_dict = {"result": response, "current_time": str(int(time.time())), "nonce": satosa_request.nonce}
    return json.dumps(response_dict)


# REGISTRATION PART

@app.route('/begin_activate', methods=['POST'])
def webauthn_begin_activate():
    '''
    This url is called when the registration process starts
    '''
    username = request.form.get('register_username')
    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)
    display_name = request.form.get('register_display_name')
    user_exists = database.user_exists(username)
    if not user_exists or not current_user.is_authenticated or not username == current_user.id:
        return make_response(jsonify({'fail': 'User not logged in.'}), 401)

    if not util.validate_token_name(display_name):
        return make_response(jsonify({'fail': 'Invalid display name.'}), 401)

    # clear session variables prior to starting a new registration
    session.pop('register_ukey', None)
    session.pop('register_username', None)
    session.pop('register_display_name', None)
    session.pop('challenge', None)

    session['register_username'] = username
    session['register_display_name'] = display_name

    challenge = util.generate_challenge(32)
    ukey = util.generate_ukey()
    session['challenge'] = challenge.rstrip('=')
    session['register_ukey'] = ukey

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, RP_NAME, RP_ID, ukey, username, display_name,
        cfg['host']['origin'])

    return jsonify(make_credential_options.registration_dict)


@app.route('/verify_credential_info', methods=['POST'])
def verify_credential_info():
    '''
    This url is called to verify and register the token
    '''
    challenge = session['challenge']
    username = session['register_username']
    display_name = session['register_display_name']
    ukey = session['register_ukey']
    user_exists = database.user_exists(username)
    if not user_exists or not current_user.is_authenticated or not username == current_user.id:
        return make_response(jsonify({'fail': 'User not logged in.'}), 401)

    registration_response = request.form
    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True
    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})
    credential_id_exists = database.credential_exists(webauthn_credential.credential_id)
    if credential_id_exists:
        return make_response(
            jsonify({
                'fail': 'Credential ID already exists.'
            }), 401)

    existing_user = database.user_exists(username)
    credential = Credential()
    if not existing_user or True:
        if sys.version_info >= (3, 0):
            webauthn_credential.credential_id = str(
                webauthn_credential.credential_id, "utf-8")
            webauthn_credential.public_key = str(
                webauthn_credential.public_key, "utf-8")
        credential.id = randint(1, 100000)
        credential.ukey = ukey
        credential.username = username
        credential.display_name = display_name
        credential.pub_key = webauthn_credential.public_key
        credential.credential_id = webauthn_credential.credential_id
        credential.sign_count = webauthn_credential.sign_count
        credential.rp_id = RP_ID
        credential.icon_url = 'https://example.com'
        database.save_credential(credential)
        database.turn_on(credential.username)
    else:
        return make_response(jsonify({'fail': 'User already exists.'}), 401)
    satosa_request = Request()
    satosa_request.userId = credential.username
    database.make_success(satosa_request)
    user = database.get_user(credential.username)
    login_user(user)
    return jsonify({'success': 'User successfully registered.'})


# LOGIN PART

@app.route('/begin_assertion', methods=['POST'])
def webauthn_begin_assertion():
    '''
    This url is called when the authentication process begins
    '''
    username = request.form.get('login_username')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)
    credentials = database.get_credentials(username)
    user = database.get_user(username)

    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    session.pop('challenge', None)
    challenge = util.generate_challenge(32)
    session['challenge'] = challenge.rstrip('=')
    webauthn_users = []
    for credential in credentials:
        webauthn_users.append(webauthn.WebAuthnUser(
            credential.ukey, credential.username, credential.display_name, credential.icon_url,
            credential.credential_id, credential.pub_key, credential.sign_count, credential.rp_id))
    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_users, challenge)

    return jsonify(webauthn_assertion_options.assertion_dict)


@app.route('/verify_assertion', methods=['POST'])
def verify_assertion():
    '''
    This url is called to authenticate the user
    '''
    challenge = session.get('challenge')
    assertion_response = request.form
    credential_id = assertion_response.get('id')
    credential = database.get_credential(credential_id)
    if not credential:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)

    webauthn_user = webauthn.WebAuthnUser(
        credential.ukey, credential.username, credential.display_name, credential.icon_url,
        credential.credential_id, credential.pub_key, credential.sign_count, credential.rp_id)

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        uv_required=False)  # User Verification

    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        raise e
        return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

    # Update counter.
    credential.sign_count = sign_count
    database.increment_sign_count(credential)

    satosa_request = Request()
    satosa_request.userId = credential.username
    database.make_success(satosa_request)
    user = User()
    user.id = credential.username
    login_user(user)
    return jsonify({'success': 'User successfully logged in.'})


@app.route('/logout')
@login_required
def logout():
    request = database.get_request_by_user_id(current_user.id)
    logout_user()
    return redirect(cfg['caller']['callback-url'] + "?" + urllib.parse.urlencode({"StateId":request.nonce}))


@app.route('/turn_off_auth')
def turn_off_auth():
    '''
    This url is called to turn off the requiring of authentication
    '''
    if cfg['host']['turn-off'] and current_user.is_authenticated:
        username = current_user.id
        database.turn_off(username)
        return "off"
    return "nok"


@app.route('/turn_on_auth')
def turn_on_auth():
    '''
    This url is called to turn on the requiring of the authentication
    '''
    if cfg['host']['turn-off'] and current_user.is_authenticated:
        username = current_user.id
        database.turn_on(username)
        return "on"
    return "nok"


if __name__ == '__main__':
    app.run(host= '0.0.0.0', port=80)
