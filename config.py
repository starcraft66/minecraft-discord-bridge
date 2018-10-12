import json

class Configuration(object):
    def __init__(self, path):
        try:
            with open(path, 'r') as f:
                self._config = json.load(f)
            if self._config:
                self.webhook_url = self._config["MAIN"]["WEBHOOK_URL"]
            else:
                print("error reading config")
                exit(1)
        except IOError:
            print("error reading config")
            exit(1)