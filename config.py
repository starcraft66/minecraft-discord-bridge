import json

class Configuration(object):
    def __init__(self, path):
        try:
            with open(path, 'r') as f:
                self._config = json.load(f)
            if self._config:
                self.webhook_url = self._config["MAIN"]["WEBHOOK_URL"]
                self.mc_username = self._config["MAIN"]["MC_USERNAME"]
                self.mc_password = self._config["MAIN"]["MC_PASSWORD"]
                self.mc_server = self._config["MAIN"]["MC_SERVER"]
                self.mc_port = self._config["MAIN"]["MC_PORT"]
                self.mc_online = self._config["MAIN"]["MC_ONLINE"]
                self.discord_token = self._config["MAIN"]["DISCORD_APP_TOKEN"]
                self.logging_level = self._config["MAIN"]["LOG_LEVEL"]
                self.admin_users = self._config["MAIN"]["ADMINS"]
                self.auth_ip = self._config["AUTH_SERVER"]["BIND_IP"]
                self.auth_port = self._config["AUTH_SERVER"]["PORT"]
                self.auth_dns = self._config["AUTH_SERVER"]["DNS_WILDCARD"]
                self.database_connection_string = self._config["DATABASE"]["CONNECTION_STRING"]
            else:
                print("error reading config")
                exit(1)
        except IOError:
            print("error reading config")
            exit(1)