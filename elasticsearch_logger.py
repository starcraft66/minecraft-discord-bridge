import time
from enum import Enum
import logging

import requests

_username = None
_password = None
_auth = None
_url = None

log = logging.getLogger("bridge.elasticsearch")


def initialize(config):
    global _username, _password, _url, _auth
    if config.es_auth:
        _auth = True
        _username = config.es_username
        _password = config.es_password
    _url = config.es_url


def log_connection(uuid, reason, count=0):
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
    post_request("connections/_doc/", es_payload)


def log_chat_message(uuid, display_name, message, message_unformatted):
    es_payload = {
        "uuid": uuid,
        "display_name": display_name,
        "message": message,
        "message_unformatted": message_unformatted,
        "time": (lambda: int(round(time.time() * 1000)))(),
    }
    post_request("chat_messages/_doc/", es_payload)


def log_raw_message(type, message):
    es_payload = {
        "time": (lambda: int(round(time.time() * 1000)))(),
        "type": type,
        "message": message,
    }
    post_request("raw_messages/_doc/", es_payload)


def post_request(endpoint, payload):
    the_url = "{}{}".format(_url, endpoint)
    if _auth:
        post = requests.post(the_url, auth=(_username, _password), json=payload)
    else:
        post = requests.post(the_url, json=payload)
    log.debug(post.text)


class ConnectionReason(Enum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    SEEN = "SEEN"
