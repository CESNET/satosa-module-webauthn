from database import Database
import yaml

with open("config.yaml", "r") as ymlfile:
    cfg = yaml.load(ymlfile)

database = Database(cfg)
print(database.create_database())
print("Script finished.")
