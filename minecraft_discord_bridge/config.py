#
# Copyright (c) 2018 Tristan Gosselin-Hane.
#
# This file is part of minecraft-discord-bridge
# (see https://github.com/starcraft66/minecraft-discord-bridge).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import json
import logging


class Configuration(object):
    def __init__(self, path):
        self.logger = logging.getLogger("bridge.config")
        try:
            with open(path, 'r') as file:
                self._config = json.load(file)
            if self._config:
                self.mc_username = self._config["MAIN"]["MC_USERNAME"]
                self.mc_password = self._config["MAIN"]["MC_PASSWORD"]
                self.mc_server = self._config["MAIN"]["MC_SERVER"]
                self.mc_port = self._config["MAIN"]["MC_PORT"]
                self.mc_online = self._config["MAIN"]["MC_ONLINE"]
                self.discord_token = self._config["MAIN"]["DISCORD_APP_TOKEN"]
                self.logging_level = self._config["MAIN"]["LOG_LEVEL"]
                self.message_delay = self._config["MAIN"]["MESSAGE_DELAY"]
                self.failsafe_retries = self._config["MAIN"]["FAILSAFE_RETRIES"]
                self.vanilla_chat_mode = self._config["MAIN"]["VANILLA_CHAT_MODE"]
                self.admin_users = self._config["MAIN"]["ADMINS"]
                self.auth_ip = self._config["AUTH_SERVER"]["BIND_IP"]
                self.auth_port = self._config["AUTH_SERVER"]["PORT"]
                self.auth_dns = self._config["AUTH_SERVER"]["DNS_WILDCARD"]
                self.database_connection_string = self._config["DATABASE"]["CONNECTION_STRING"]
                self.es_enabled = self._config["ELASTICSEARCH"]["ENABLED"]
                self.es_url = self._config["ELASTICSEARCH"]["URL"]
                self.es_auth = self._config["ELASTICSEARCH"]["AUTH"]
                self.es_username = self._config["ELASTICSEARCH"]["USERNAME"]
                self.es_password = self._config["ELASTICSEARCH"]["PASSWORD"]
                self.debugging_enabled = self._config["DEBUGGING"]["ENABLED"]
                self.debugging_ip = self._config["DEBUGGING"]["BIND_IP"]
                self.debugging_port = self._config["DEBUGGING"]["PORT"]
            else:
                self.logger.error("error reading config")
                exit(1)
        except IOError:
            self.logger.error("error reading config")
            exit(1)
