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

import time
from enum import Enum
import logging

import requests_futures


class ElasticsearchLogger():
    def __init__(self, futures_session: requests_futures.sessions, url: str, username: str = "", password: str = ""):
        self.futures_session = futures_session
        self.url = url
        self.username = username
        self.password = password
        self.log = logging.getLogger("bridge.elasticsearch")

    def log_connection(self, uuid, reason, count=0):
        if ConnectionReason(reason).name != "SEEN":
            es_payload = {
                "uuid": uuid,
                "time": (lambda: int(round(time.time() * 1000)))(),
                "reason": ConnectionReason(reason).name,
                "count": count,
            }
        else:
            es_payload = {
                "uuid": uuid,
                "time": (lambda: int(round(time.time() * 1000)))(),
                "reason": ConnectionReason(reason).name,
            }
        self.post_request("connections/_doc/", es_payload)

    def log_chat_message(self, uuid, display_name, message, message_unformatted):
        es_payload = {
            "uuid": uuid,
            "display_name": display_name,
            "message": message,
            "message_unformatted": message_unformatted,
            "time": (lambda: int(round(time.time() * 1000)))(),
        }
        self.post_request("chat_messages/_doc/", es_payload)

    def log_raw_message(self, msg_type, message):
        es_payload = {
            "time": (lambda: int(round(time.time() * 1000)))(),
            "type": msg_type,
            "message": message,
        }
        self.post_request("raw_messages/_doc/", es_payload)

    def post_request(self, endpoint, payload):
        the_url = f"{self.url}{endpoint}"
        if self.username and self.password:
            future = self.futures_session.post(the_url, auth=(self.username, self.password), json=payload)
        else:
            future = self.futures_session.post(the_url, json=payload)
        self.log.debug(future.result().text)


class ConnectionReason(Enum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    SEEN = "SEEN"
