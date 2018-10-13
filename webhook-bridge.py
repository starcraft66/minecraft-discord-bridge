#!/usr/bin/env python

from __future__ import print_function

import getpass
import sys
import re
import requests
import json
import time
from optparse import OptionParser
from config import Configuration
from database import DiscordChannel
import database_session

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound
from minecraft.compat import input

import discord
import asyncio

UUID_CACHE = {}

def main():
    config = Configuration("config.json")

    WEBHOOK_URL = config.webhook_url

    database_session.initialize(config)

    def handle_disconnect(join_game_packet):
        print('Disconnected.')
        nonlocal connection
        connection.disconnect(immediate=True)
        time.sleep(5)
        print('Reconnecting.')
        if not config.mc_online:
            print("Connecting in offline mode...")
            connection = Connection(
                config.mc_server, config.mc_port, username=config.mc_username,
                handle_exception=handle_disconnect)
        else:
            auth_token = authentication.AuthenticationToken()
            try:
                auth_token.authenticate(config.mc_username, config.mc_password)
            except YggdrasilError as e:
                print(e)
                sys.exit()
            print("Logged in as %s..." % auth_token.username)
            connection = Connection(
                config.mc_server, config.mc_port, auth_token=auth_token,
                handle_exception=handle_disconnect)
        register_handlers(connection)
        connection.connect()

    if not config.mc_online:
        print("Connecting in offline mode...")
        connection = Connection(
            config.mc_server, config.mc_port, username=config.mc_username,
            handle_exception=handle_disconnect)
    else:
        auth_token = authentication.AuthenticationToken()
        try:
            auth_token.authenticate(config.mc_username, config.mc_password)
        except YggdrasilError as e:
            print(e)
            sys.exit()
        print("Logged in as %s..." % auth_token.username)
        connection = Connection(
            config.mc_server, config.mc_port, auth_token=auth_token,
            handle_exception=handle_disconnect)

    #Initialize the discord part
    discord_bot = discord.Client()

    def register_handlers(connection):
        connection.register_packet_listener(
            handle_join_game, clientbound.play.JoinGamePacket)

        connection.register_packet_listener(
            print_chat, clientbound.play.ChatMessagePacket)

        connection.register_packet_listener(
            handle_health_update, clientbound.play.UpdateHealthPacket)

        connection.register_packet_listener(
            handle_disconnect, clientbound.play.DisconnectPacket)


    def handle_join_game(join_game_packet):
        print('Connected.')

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

    def handle_health_update(health_update_packet):
        if health_update_packet.health <= 0:
            #We need to respawn!!!!
            print("Respawned the player because it died!")
            packet = serverbound.play.ClientStatusPacket()
            packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
            connection.write_packet(packet)

    register_handlers(connection)

    connection.connect()

    @discord_bot.event
    async def on_ready():
        print("Discord bot logged in as {} ({})".format(discord_bot.user.name, discord_bot.user.id))

    @discord_bot.event
    async def on_message(message):
        this_channel = message.channel.id
        if message.content.startswith("mc!chathere"):
            session = database_session.get_session()
            channels = session.query(DiscordChannel).filter_by(channel_id=this_channel).all()
            print(channels)
            if not channels:
                new_channel = DiscordChannel(this_channel)
                session.add(new_channel)
                session.commit()
                session.close()
                del session
                msg = "The bot will now start chatting here! To stop this, run `mc!stopchathere`."
                await discord_bot.send_message(message.channel, msg)
            else:
                msg = "The bot is already chatting in this channel! To stop this, run `mc!stopchathere`."
                await discord_bot.send_message(message.channel, msg)
                return

        elif message.content.startswith("mc!stopchathere"):
            session = database_session.get_session()
            channels = session.query(DiscordChannel).all()
            deleted = session.query(DiscordChannel).filter_by(channel_id=this_channel).delete()
            session.commit()
            session.close()
            print(deleted)
            if deleted < 1:
                msg = "The bot was not chatting here!"
                await discord_bot.send_message(message.channel, msg)
                return
            else:
                msg = "The bot will no longer here!"
                await discord_bot.send_message(message.channel, msg)
                return
            
        elif not message.author.bot:
            await discord_bot.delete_message(message)
            packet = serverbound.play.ChatPacket()
            packet.message = "{}: {}".format(message.author.name, message.content)
            connection.write_packet(packet)

    discord_bot.run(config.discord_token)

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
    
