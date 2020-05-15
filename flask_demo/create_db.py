from database import Database
import yaml

with open("/var/webauthn-module/py_webauthn/flask_demo/config.yaml", "r") as ymlfile:
    cfg = yaml.load(ymlfile)

database = Database(cfg)
print(database.create_database())
print("Script finished.")




