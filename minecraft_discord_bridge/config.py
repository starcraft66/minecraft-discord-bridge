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
import os


def get_config_value(json_config, section, key):
    env_value = os.getenv("MDB_" + section.upper() + "_" + key.upper(), None)
    if env_value is not None:
        return env_value
    return json_config[section.upper()][key.upper()]


class Configuration(object):
    def __init__(self, path):
        self.logger = logging.getLogger("bridge.config")
        try:
            with open(path, 'r', encoding="utf-8") as file:
                self._config = json.load(file)
            if self._config:
                self.mc_username = get_config_value(self._config, "MAIN", "MC_USERNAME")
                self.mc_password = get_config_value(self._config, "MAIN", "MC_PASSWORD")
                self.mc_server = get_config_value(self._config, "MAIN", "MC_SERVER")
                self.mc_port = get_config_value(self._config, "MAIN", "MC_PORT")
                self.mc_online = get_config_value(self._config, "MAIN", "MC_ONLINE")
                self.discord_token = get_config_value(self._config, "MAIN", "DISCORD_APP_TOKEN")
                self.logging_level = get_config_value(self._config, "MAIN", "LOG_LEVEL")
                self.message_delay = get_config_value(self._config, "MAIN", "MESSAGE_DELAY")
                self.failsafe_retries = get_config_value(self._config, "MAIN", "FAILSAFE_RETRIES")
                self.vanilla_chat_mode = get_config_value(self._config, "MAIN", "VANILLA_CHAT_MODE")
                self.admin_users = get_config_value(self._config, "MAIN", "ADMINS")
                self.auth_ip = get_config_value(self._config, "AUTH", "SERVER_BIND_IP")
                self.auth_port = get_config_value(self._config, "AUTH", "SERVER_PORT")
                self.auth_dns = get_config_value(self._config, "AUTH", "SERVER_DNS_WILDCARD")
                self.database_connection_string = get_config_value(self._config, "DATABASE", "CONNECTION_STRING")
                self.es_enabled = get_config_value(self._config, "ELASTICSEARCH", "ENABLED")
                self.es_url = get_config_value(self._config, "ELASTICSEARCH", "URL")
                self.es_auth = get_config_value(self._config, "ELASTICSEARCH", "AUTH")
                self.es_username = get_config_value(self._config, "ELASTICSEARCH", "USERNAME")
                self.es_password = get_config_value(self._config, "ELASTICSEARCH", "PASSWORD")
                self.debugging_enabled = get_config_value(self._config, "DEBUGGING", "ENABLED")
                self.debugging_ip = get_config_value(self._config, "DEBUGGING", "BIND_IP")
                self.debugging_port = get_config_value(self._config, "DEBUGGING", "PORT")
            else:
                self.logger.error("error reading config")
                exit(1)
        except IOError:
            self.logger.error("error reading config")
            exit(1)
