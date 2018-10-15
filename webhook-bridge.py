#!/usr/bin/env python

from __future__ import print_function

import getpass
import sys
import re
import requests
import json
import time
import logging
import random
import string
from threading import Thread
from optparse import OptionParser
from config import Configuration
from database import DiscordChannel, AccountLinkToken, MinecraftAccount, DiscordAccount
import database_session

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound
from minecraft.compat import input

import discord
import asyncio

from mcstatus import MinecraftServer

from bidict import bidict

UUID_CACHE = bidict()

def mc_uuid_to_username(uuid):
    if uuid not in UUID_CACHE:
        try:
            short_uuid = uuid.replace("-", "")
            mojang_response = requests.get("https://api.mojang.com/user/profiles/{}/names".format(short_uuid)).json()
            if len(mojang_response) > 1:
                # Multiple name changes
                player_username = mojang_response[:-1]["name"]
            else:
                # Only one name
                player_username = mojang_response[0]["name"]
            UUID_CACHE[uuid] = player_username
            return player_username
        except:
            logging.error("Failed to lookup {}'s username using the Mojang API.".format(uuid))
    else:
        return UUID_CACHE[uuid]

    
def mc_username_to_uuid(username):
    if username not in UUID_CACHE:
        try:
            player_uuid = requests.get("https://api.mojang.com/users/profiles/minecraft/{}".format(username)).json()["id"]
            UUID_CACHE[username] = player_uuid
            return player_uuid
        except:
            logging.error("Failed to lookup {}'s UUID using the Mojang API.".format(username))
    else:
        return UUID_CACHE[username]


def setup_logging(level):
    if level.lower() == "debug":
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    log_format = "%(asctime)s:%(levelname)s:%(message)s"
    logging.basicConfig(filename="bridge_log.log", format=log_format, level=log_level)
    stdout_logger=logging.StreamHandler(sys.stdout)
    stdout_logger.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(stdout_logger)


def run_auth_server(port):
    # We need to import twisted after setting up the logger because twisted hijacks our logging
    # TODO: Fix this in a cleaner way
    from twisted.internet import reactor
    from auth_server import AuthFactory

    # Create factory
    factory = AuthFactory()

    # Listen
    logging.info("Starting authentication server on port {}".format(port))

    factory.listen("", port)
    try:
        reactor.run(installSignalHandlers=False)
    except KeyboardInterrupt:
        reactor.stop()


def generate_random_auth_token(length):
    letters = string.ascii_lowercase + string.digits + string.ascii_uppercase
    return ''.join(random.choice(letters) for i in range(length))


def main():
    config = Configuration("config.json")
    setup_logging(config.logging_level)

    WEBHOOK_URL = config.webhook_url

    database_session.initialize(config)

    reactor_thread = Thread(target=run_auth_server, args=(config.auth_port,))
    reactor_thread.start()

    def handle_disconnect():
        logging.info('Disconnected.')
        connection.disconnect(immediate=True)
        time.sleep(5)
        while not is_server_online():
            logging.info('Not reconnecting to server because it appears to be offline.')
            time.sleep(5)
        logging.info('Reconnecting.')
        connection.connect()

    def handle_disconnect_packet(join_game_packet):
        handle_disconnect()

    def minecraft_handle_exception(exception, exc_info):
        logging.info("{}: {}".format(exception, exc_info))
        handle_disconnect()

    def is_server_online():
        server = MinecraftServer.lookup("{}:{}".format(config.mc_server, config.mc_port))
        try:
            status = server.status()
            del status
            return True
        except:
            # The server is offline
            return False

    logging.debug("Checking if the server {} is online before connecting.")

    if not config.mc_online:
        logging.info("Connecting in offline mode...")
        if not is_server_online():
            logging.info('Not connecting to server because it appears to be offline.')
            sys.exit(1)
        connection = Connection(
            config.mc_server, config.mc_port, username=config.mc_username,
            handle_exception=minecraft_handle_exception)
    else:
        auth_token = authentication.AuthenticationToken()
        try:
            auth_token.authenticate(config.mc_username, config.mc_password)
        except YggdrasilError as e:
            logging.info(e)
            sys.exit()
        global BOT_USERNAME
        BOT_USERNAME = auth_token.username
        logging.info("Logged in as %s..." % auth_token.username)
        if not is_server_online():
            logging.info('Not connecting to server because it appears to be offline.')
            sys.exit(1)
        connection = Connection(
            config.mc_server, config.mc_port, auth_token=auth_token,
            handle_exception=minecraft_handle_exception)

    #Initialize the discord part
    discord_bot = discord.Client()

    def register_handlers(connection):
        connection.register_packet_listener(
            handle_join_game, clientbound.play.JoinGamePacket)

        connection.register_packet_listener(
            handle_chat, clientbound.play.ChatMessagePacket)

        connection.register_packet_listener(
            handle_health_update, clientbound.play.UpdateHealthPacket)

        connection.register_packet_listener(
            handle_disconnect_packet, clientbound.play.DisconnectPacket)

        connection.register_packet_listener(
            handle_tab_list, clientbound.play.PlayerListItemPacket)

    def handle_tab_list(tab_list_packet):
        logging.debug("Processing tab list packet")
        for action in tab_list_packet.actions:
            if isinstance(action, clientbound.play.PlayerListItemPacket.AddPlayerAction):
                logging.debug("Processing AddPlayerAction tab list packet, name: {}, uuid: {}".format(action.name, action.uuid))
                if action.name not in UUID_CACHE:
                    UUID_CACHE[action.name] = action.uuid
            if isinstance(action, clientbound.play.PlayerListItemPacket.RemovePlayerAction):
                logging.debug("Processing RemovePlayerAction tab list packet, uuid: {}".format(action.uuid))
                for username in UUID_CACHE:
                    if UUID_CACHE[username] == action.uuid:
                        del UUID_CACHE[username]
                        break

    def handle_join_game(join_game_packet):
        logging.info('Connected.')

    def handle_chat(chat_packet):
        json_data = json.loads(chat_packet.json_data)
        if "extra" not in json_data:
            return
        chat_string = ""
        for chat_component in json_data["extra"]:
            chat_string += chat_component["text"] 

        # Handle join/leave
        regexp_match = re.match("^(.*) (joined|left) the game", chat_string, re.M|re.I)
        if regexp_match:
            logging.info("Username: {} Status: {} the game".format(regexp_match.group(1), regexp_match.group(2)))
            username = regexp_match.group(1)
            status = regexp_match.group(2)
            player_uuid = mc_username_to_uuid(username)
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
            player_uuid = mc_username_to_uuid(username)
            logging.info("Username: {} Message: {}".format(username, message))
            webhook_payload = {'username': username, 'avatar_url':  "https://visage.surgeplay.com/face/160/{}".format(player_uuid),
                'embeds': [{'title': '{}'.format(message)}]}
            post = requests.post(WEBHOOK_URL,json=webhook_payload)    

    def handle_health_update(health_update_packet):
        if health_update_packet.health <= 0:
            #We need to respawn!!!!
            logging.debug("Respawned the player because it died")
            packet = serverbound.play.ClientStatusPacket()
            packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
            connection.write_packet(packet)

    register_handlers(connection)

    connection.connect()

    @discord_bot.event
    async def on_ready():
        logging.info("Discord bot logged in as {} ({})".format(discord_bot.user.name, discord_bot.user.id))


    @discord_bot.event
    async def on_message(message):
        # We do not want the bot to reply to itself
        if message.author == discord_bot.user:
            return
        this_channel = message.channel.id
        if isinstance(message.channel, discord.abc.PrivateChannel):
            if message.content.startswith("mc!help"):
                return
            if message.content.startswith("mc!somethingelse"):
                return
            if message.content.startswith("mc!register"):
                session = database_session.get_session()
                discord_account = session.query(DiscordAccount).filter_by(discord_id=message.author.id).first()
                if not discord_account:
                    new_discord_account = DiscordAccount(message.author.id)
                    session.add(new_discord_account)
                    session.commit()
                    discord_account = session.query(DiscordAccount).filter_by(discord_id=message.author.id).first()

                new_token = generate_random_auth_token(16)
                account_link_token = AccountLinkToken(message.author.id, new_token)
                discord_account.link_token = account_link_token
                session.add(account_link_token)
                session.commit()
                msg = "Please connect your minecraft account to `{}.{}:{}` in order to link it to this bridge!".format(new_token, config.auth_dns, config.auth_port)
                session.close()
                await message.channel.send(msg)
                return
            else:
                msg = "Unknown command, type `mc!help` for a list of commands."
                await message.channel.send(msg)
                return
        if message.content.startswith("mc!chathere"):
            session = database_session.get_session()
            channels = session.query(DiscordChannel).filter_by(channel_id=this_channel).all()
            if not channels:
                new_channel = DiscordChannel(this_channel)
                session.add(new_channel)
                session.commit()
                session.close()
                del session
                msg = "The bot will now start chatting here! To stop this, run `mc!stopchathere`."
                await message.channel.send(msg)
            else:
                msg = "The bot is already chatting in this channel! To stop this, run `mc!stopchathere`."
                await message.channel.send(msg)
                return

        elif message.content.startswith("mc!stopchathere"):
            session = database_session.get_session()
            channels = session.query(DiscordChannel).all()
            deleted = session.query(DiscordChannel).filter_by(channel_id=this_channel).delete()
            session.commit()
            session.close()
            if deleted < 1:
                msg = "The bot was not chatting here!"
                await message.channel.send(msg)
                return
            else:
                msg = "The bot will no longer here!"
                await message.channel.send(msg)
                return
            
        elif not message.author.bot:
            await message.delete()
            packet = serverbound.play.ChatPacket()
            packet.message = "{}: {}".format(message.author.name, message.content)
            connection.write_packet(packet)

    discord_bot.run(config.discord_token)

    while True:
        try:
            text = input()
            if text == "/respawn":
                logging.info("respawning...")
                packet = serverbound.play.ClientStatusPacket()
                packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
                connection.write_packet(packet)
            else:
                packet = serverbound.play.ChatPacket()
                packet.message = text
                connection.write_packet(packet)
        except KeyboardInterrupt:
            logging.info("Bye!")
            sys.exit()
 

if __name__ == "__main__":
    main()
    
