from flask_login import UserMixin
import time
class User(UserMixin):
    def __init__(self):
        self.id = None
        self.databaseId = None
        self.turned_off = None

class Credential:
    def __init__(self):
        self.id = None
        self.ukey = None
        self.credential_id = None
        self.display_name = None
        self.pub_key = None
        self.sign_count = None
        self.username = None
        self.rp_id = None
        self.icon_url = None

class Request:
    def __init__(self, data=None):
        if data is None:
            self.userId = None
            self.nonce = None
            self.time = None
        else:
            self.userId = data['user_id']
            self.nonce = data['nonce']
            self.time = data['time']


    def is_request_new(self):
        if time.time() - int(self.time) > 60:
            return False
        return True
