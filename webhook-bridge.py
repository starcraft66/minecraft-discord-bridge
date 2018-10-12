#!/usr/bin/env python

from __future__ import print_function

import getpass
import sys
import re
import requests
import json
from optparse import OptionParser
from config import Configuration

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound
from minecraft.compat import input

import discord
import asyncio

UUID_CACHE = {}

def get_options():
    parser = OptionParser()

    parser.add_option("-u", "--username", dest="username", default=None,
                      help="username to log in with")

    parser.add_option("-p", "--password", dest="password", default=None,
                      help="password to log in with")

    parser.add_option("-s", "--server", dest="server", default=None,
                      help="server host or host:port "
                           "(enclose IPv6 addresses in square brackets)")

    parser.add_option("-o", "--offline", dest="offline", action="store_true",
                      help="connect to a server in offline mode "
                           "(no password required)")

    parser.add_option("-t", "--token", dest="discord_token", default=None,
                      help="discord token to log the bot in with")

    (options, args) = parser.parse_args()

    if not options.username:
        options.username = input("Enter your username: ")

    if not options.password and not options.offline:
        options.password = getpass.getpass("Enter your password (leave "
                                           "blank for offline mode): ")
        options.offline = options.offline or (options.password == "")

    if not options.server:
        options.server = input("Enter server host or host:port "
                               "(enclose IPv6 addresses in square brackets): ")
    # Try to split out port and address
    match = re.match(r"((?P<host>[^\[\]:]+)|\[(?P<addr>[^\[\]]+)\])"
                     r"(:(?P<port>\d+))?$", options.server)
    if match is None:
        raise ValueError("Invalid server address: '%s'." % options.server)
    options.address = match.group("host") or match.group("addr")
    options.port = int(match.group("port") or 25565)

    return options


def main():
    options = get_options()

    config = Configuration("config.json")

    WEBHOOK_URL = config.webhook_url

    if options.offline:
        print("Connecting in offline mode...")
        connection = Connection(
            options.address, options.port, username=options.username)
    else:
        auth_token = authentication.AuthenticationToken()
        try:
            auth_token.authenticate(options.username, options.password)
        except YggdrasilError as e:
            print(e)
            sys.exit()
        print("Logged in as %s..." % auth_token.username)
        connection = Connection(
            options.address, options.port, auth_token=auth_token)

    #Initialize the discord part
    discord_bot = discord.Client()

    def handle_join_game(join_game_packet):
        print('Connected.')

    connection.register_packet_listener(
        handle_join_game, clientbound.play.JoinGamePacket)

    def print_chat(chat_packet):

        json_data = json.loads(chat_packet.json_data)
        if "extra" not in json_data:
            return
        chat_string = ""
        for chat_component in json_data["extra"]:
            chat_string += chat_component["text"] 

        # Handle join/leave
        regexp_match = re.match("^(.*) (joined|left) the game", chat_string, re.M|re.I)
        if regexp_match:
            print("Username: {} Status: {} the game".format(regexp_match.group(1), regexp_match.group(2)))
            username = regexp_match.group(1)
            status = regexp_match.group(2)
            if username not in UUID_CACHE:
                player_uuid = requests.get("https://api.mojang.com/users/profiles/minecraft/{}".format(username)).json()["id"]
                UUID_CACHE[username] = player_uuid
            else:
                player_uuid = UUID_CACHE[username]
            if status == "joined":
                webhook_payload = {'username': username, 'avatar_url':  "https://visage.surgeplay.com/face/160/{}".format(player_uuid),
                    'content': '', 'embeds': [{'color': 65280, 'title': '**Joined the game**'}]}
            elif status == "left":
                webhook_payload = {'username': username, 'avatar_url':  "https://visage.surgeplay.com/face/160/{}".format(player_uuid),
                    'content': '', 'embeds': [{'color': 16711680, 'title': '**Left the game**'}]}
            else:
                return
            post = requests.post(WEBHOOK_URL,json=webhook_payload)
            
        
        # Handle chat message
        regexp_match = re.match("<(.*?)> (.*)", chat_string, re.M|re.I)
        if regexp_match:
            username = regexp_match.group(1)
            message = regexp_match.group(2)
            if username not in UUID_CACHE:
                player_uuid = requests.get("https://api.mojang.com/users/profiles/minecraft/{}".format(username)).json()["id"]
                UUID_CACHE[username] = player_uuid
            else:
                player_uuid = UUID_CACHE[username]
            print("Username: {} Message: {}".format(username, message))
            webhook_payload = {'username': username, 'avatar_url':  "https://visage.surgeplay.com/face/160/{}".format(player_uuid),
                'embeds': [{'title': '{}'.format(message)}]}
            post = requests.post(WEBHOOK_URL,json=webhook_payload)        

    connection.register_packet_listener(
        print_chat, clientbound.play.ChatMessagePacket)

    connection.connect()

    @discord_bot.event
    async def on_ready():
        print("Discord bot logged in as {} ({})".format(discord_bot.user.name, discord_bot.user.id))

    @discord_bot.event
    async def on_message(message):
        if not message.author.bot:
            await discord_bot.delete_message(message)
            packet = serverbound.play.ChatPacket()
            packet.message = "{}: {}".format(message.author.name, message.content)
            connection.write_packet(packet)

    discord_bot.run(options.discord_token)

    while True:
        try:
            text = input()
            if text == "/respawn":
                print("respawning...")
                packet = serverbound.play.ClientStatusPacket()
                packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
                connection.write_packet(packet)
            else:
                packet = serverbound.play.ChatPacket()
                packet.message = text
                connection.write_packet(packet)
        except KeyboardInterrupt:
            print("Bye!")
            sys.exit()
 

if __name__ == "__main__":
    main()
    
