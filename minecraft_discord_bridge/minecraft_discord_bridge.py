#!/usr/bin/env python

from __future__ import print_function

import sys
import re
import json
import time
import logging
import random
import string
import uuid
import asyncio
from threading import Thread
from datetime import datetime, timedelta, timezone

import requests
from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import clientbound, serverbound
import discord
from mcstatus import MinecraftServer
from bidict import bidict

from .database_session import DatabaseSession
from .elasticsearch_logger import ElasticsearchLogger, ConnectionReason
from .config import Configuration
from .database import DiscordChannel, AccountLinkToken, DiscordAccount


class MinecraftDiscordBridge():
    def __init__(self):
        self.session_token = ""
        self.uuid_cache = bidict()
        self.webhooks = []
        self.bot_username = ""
        self.next_message_time = datetime.now(timezone.utc)
        self.previous_message = ""
        self.player_list = bidict()
        self.previous_player_list = bidict()
        self.accept_join_events = False
        self.tab_header = ""
        self.tab_footer = ""
        # Initialize the discord part
        self.discord_bot = discord.Client()
        self.config = Configuration("config.json")
        self.auth_token = None
        self.connection = None
        self.setup_logging(self.config.logging_level)
        self.database_session = DatabaseSession()
        self.logger = logging.getLogger("bridge")
        self.database_session.initialize(self.config)
        # We need to import twisted after setting up the logger because twisted hijacks our logging
        from . import auth_server
        auth_server.DATABASE_SESSION = self.database_session
        if self.config.es_enabled:
            if self.config.es_auth:
                self.es_logger = ElasticsearchLogger(
                    self.config.es_url, self.config.es_username, self.config.es_password)
            else:
                self.es_logger = ElasticsearchLogger(self.config.es_url)

        @self.discord_bot.event
        async def on_ready():  # pylint: disable=W0612
            self.logger.info("Discord bot logged in as %s (%s)", self.discord_bot.user.name, self.discord_bot.user.id)
            self.webhooks = []
            session = self.database_session.get_session()
            channels = session.query(DiscordChannel).all()
            session.close()
            for channel in channels:
                channel_id = channel.channel_id
                discord_channel = self.discord_bot.get_channel(channel_id)
                channel_webhooks = await discord_channel.webhooks()
                found = False
                for webhook in channel_webhooks:
                    if webhook.name == "_minecraft" and webhook.user == self.discord_bot.user:
                        self.webhooks.append(webhook.url)
                        found = True
                    self.logger.debug("Found webhook %s in channel %s", webhook.name, discord_channel.name)
                if not found:
                    # Create the hook
                    await discord_channel.create_webhook(name="_minecraft")

        @self.discord_bot.event
        async def on_message(message):  # pylint: disable=W0612
            # We do not want the bot to reply to itself
            if message.author == self.discord_bot.user:
                return
            this_channel = message.channel.id

            # PM Commands
            if message.content.startswith("mc!help"):
                try:
                    send_channel = message.channel
                    if isinstance(message.channel, discord.abc.GuildChannel):
                        await message.delete()
                        dm_channel = message.author.dm_channel
                        if not dm_channel:
                            await message.author.create_dm()
                        send_channel = message.author.dm_channel
                    msg = self.get_discord_help_string()
                    await send_channel.send(msg)
                except discord.errors.Forbidden:
                    if isinstance(message.author, discord.abc.User):
                        msg = "{}, please allow private messages from this bot.".format(message.author.mention)
                        error_msg = await message.channel.send(msg)
                        await asyncio.sleep(3)
                        await error_msg.delete()
                    return

            elif message.content.startswith("mc!register"):
                try:
                    send_channel = message.channel
                    if isinstance(message.channel, discord.abc.GuildChannel):
                        await message.delete()
                        dm_channel = message.author.dm_channel
                        if not dm_channel:
                            await message.author.create_dm()
                        send_channel = message.author.dm_channel
                    session = self.database_session.get_session()
                    discord_account = session.query(DiscordAccount).filter_by(discord_id=message.author.id).first()
                    if not discord_account:
                        new_discord_account = DiscordAccount(message.author.id)
                        session.add(new_discord_account)
                        session.commit()
                        discord_account = session.query(DiscordAccount).filter_by(discord_id=message.author.id).first()

                    new_token = self.generate_random_auth_token(16)
                    account_link_token = AccountLinkToken(message.author.id, new_token)
                    discord_account.link_token = account_link_token
                    session.add(account_link_token)
                    session.commit()
                    msg = "Please connect your minecraft account to `{}.{}:{}` in order to link it to this bridge!"\
                        .format(new_token, self.config.auth_dns, self.config.auth_port)
                    session.close()
                    del session
                    await send_channel.send(msg)
                except discord.errors.Forbidden:
                    if isinstance(message.author, discord.abc.User):
                        msg = "{}, please allow private messages from this bot.".format(message.author.mention)
                        error_msg = await message.channel.send(msg)
                        await asyncio.sleep(3)
                        await error_msg.delete()
                    return

            # Global Commands
            elif message.content.startswith("mc!chathere"):
                if isinstance(message.channel, discord.abc.PrivateChannel):
                    msg = "Sorry, this command is only available in public channels."
                    await message.channel.send(msg)
                    return
                if message.author.id not in self.config.admin_users:
                    await message.delete()
                    try:
                        dm_channel = message.author.dm_channel
                        if not dm_channel:
                            await message.author.create_dm()
                        dm_channel = message.author.dm_channel
                        msg = "Sorry, you do not have permission to execute that command!"
                        await dm_channel.send(msg)
                    except discord.errors.Forbidden:
                        if isinstance(message.author, discord.abc.User):
                            msg = "{}, please allow private messages from this bot.".format(message.author.mention)
                            error_msg = await message.channel.send(msg)
                            await asyncio.sleep(3)
                            await error_msg.delete()
                        return
                session = self.database_session.get_session()
                channels = session.query(DiscordChannel).filter_by(channel_id=this_channel).all()
                if not channels:
                    new_channel = DiscordChannel(this_channel)
                    session.add(new_channel)
                    session.commit()
                    session.close()
                    del session
                    webhook = await message.channel.create_webhook(name="_minecraft")
                    self.webhooks.append(webhook.url)
                    msg = "The bot will now start chatting here! To stop this, run `mc!stopchathere`."
                    await message.channel.send(msg)
                else:
                    msg = "The bot is already chatting in this channel! To stop this, run `mc!stopchathere`."
                    await message.channel.send(msg)
                    return

            elif message.content.startswith("mc!stopchathere"):
                if isinstance(message.channel, discord.abc.PrivateChannel):
                    msg = "Sorry, this command is only available in public channels."
                    await message.channel.send(msg)
                    return
                if message.author.id not in self.config.admin_users:
                    await message.delete()
                    try:
                        dm_channel = message.author.dm_channel
                        if not dm_channel:
                            await message.author.create_dm()
                        dm_channel = message.author.dm_channel
                        msg = "Sorry, you do not have permission to execute that command!"
                        await dm_channel.send(msg)
                    except discord.errors.Forbidden:
                        if isinstance(message.author, discord.abc.User):
                            msg = "{}, please allow private messages from this bot.".format(message.author.mention)
                            error_msg = await message.channel.send(msg)
                            await asyncio.sleep(3)
                            await error_msg.delete()
                        return
                session = self.database_session.get_session()
                deleted = session.query(DiscordChannel).filter_by(channel_id=this_channel).delete()
                session.commit()
                session.close()
                for webhook in await message.channel.webhooks():
                    if webhook.name == "_minecraft" and webhook.user == self.discord_bot.user:
                        # Copy the list to avoid some problems since
                        # we're deleting indicies form it as we loop
                        # through it
                        if webhook.url in self.webhooks[:]:
                            self.webhooks.remove(webhook.url)
                        await webhook.delete()
                if deleted < 1:
                    msg = "The bot was not chatting here!"
                    await message.channel.send(msg)
                    return
                else:
                    msg = "The bot will no longer chat here!"
                    await message.channel.send(msg)
                    return

            elif message.content.startswith("mc!tab"):
                send_channel = message.channel
                try:
                    if isinstance(message.channel, discord.abc.GuildChannel):
                        await message.delete()
                        dm_channel = message.author.dm_channel
                        if not dm_channel:
                            await message.author.create_dm()
                        send_channel = message.author.dm_channel
                    player_list = ", ".join(list(map(lambda x: x[1], self.player_list.items())))
                    msg = "{}\n" \
                        "Players online: {}\n" \
                        "{}".format(self.escape_markdown(
                            self.strip_colour(self.tab_header)), self.escape_markdown(
                                self.strip_colour(player_list)), self.escape_markdown(
                                    self.strip_colour(self.tab_footer)))
                    await send_channel.send(msg)
                except discord.errors.Forbidden:
                    if isinstance(message.author, discord.abc.User):
                        msg = "{}, please allow private messages from this bot.".format(message.author.mention)
                        error_msg = await message.channel.send(msg)
                        await asyncio.sleep(3)
                        await error_msg.delete()
                    return

            elif message.content.startswith("mc!"):
                # Catch-all
                send_channel = message.channel
                try:
                    if isinstance(message.channel, discord.abc.GuildChannel):
                        await message.delete()
                        dm_channel = message.author.dm_channel
                        if not dm_channel:
                            await message.author.create_dm()
                        send_channel = message.author.dm_channel
                    msg = "Unknown command, type `mc!help` for a list of commands."
                    await send_channel.send(msg)
                except discord.errors.Forbidden:
                    if isinstance(message.author, discord.abc.User):
                        msg = "{}, please allow private messages from this bot.".format(message.author.mention)
                        error_msg = await message.channel.send(msg)
                        await asyncio.sleep(3)
                        await error_msg.delete()
                    return

            elif not message.author.bot:
                session = self.database_session.get_session()
                channel_should_chat = session.query(DiscordChannel).filter_by(channel_id=this_channel).first()
                if channel_should_chat:
                    await message.delete()
                    discord_user = session.query(DiscordAccount).filter_by(discord_id=message.author.id).first()
                    if discord_user:
                        if discord_user.minecraft_account:
                            minecraft_uuid = discord_user.minecraft_account.minecraft_uuid
                            session.close()
                            del session
                            minecraft_username = self.mc_uuid_to_username(minecraft_uuid)

                            # Max chat message length: 256, bot username does not count towards this
                            # Does not count|Counts
                            # <BOT_USERNAME> minecraft_username: message
                            padding = 2 + len(minecraft_username)

                            message_to_send = self.remove_emoji(
                                message.clean_content.encode('utf-8').decode('ascii', 'replace')).strip()
                            message_to_discord = self.escape_markdown(message.clean_content)

                            total_len = padding + len(message_to_send)
                            if total_len > 256:
                                message_to_send = message_to_send[:(256 - padding)]
                                message_to_discord = message_to_discord[:(256 - padding)]
                            elif not message_to_send:
                                return

                            session = self.database_session.get_session()
                            channels = session.query(DiscordChannel).all()
                            session.close()
                            del session
                            if message_to_send == self.previous_message or \
                                    datetime.now(timezone.utc) < self.next_message_time:
                                send_channel = message.channel
                                try:
                                    if isinstance(message.channel, discord.abc.GuildChannel):
                                        dm_channel = message.author.dm_channel
                                        if not dm_channel:
                                            await message.author.create_dm()
                                        send_channel = message.author.dm_channel
                                    msg = "Your message \"{}\" has been rate-limited.".format(message.clean_content)
                                    await send_channel.send(msg)
                                except discord.errors.Forbidden:
                                    if isinstance(message.author, discord.abc.User):
                                        msg = "{}, please allow private messages from this bot.".format(
                                            message.author.mention)
                                        error_msg = await message.channel.send(msg)
                                        await asyncio.sleep(3)
                                        await error_msg.delete()
                                    return

                            self.previous_message = message_to_send
                            self.next_message_time = datetime.now(timezone.utc) + timedelta(
                                seconds=self.config.message_delay)

                            self.logger.info("Outgoing message from discord: Username: %s Message: %s",
                                             minecraft_username, message_to_send)

                            for channel in channels:
                                webhooks = await self.discord_bot.get_channel(channel.channel_id).webhooks()
                                for webhook in webhooks:
                                    if webhook.name == "_minecraft":
                                        await webhook.send(
                                            username=minecraft_username,
                                            avatar_url="https://visage.surgeplay.com/face/160/{}".format(
                                                minecraft_uuid),
                                            content=message_to_discord)

                            packet = serverbound.play.ChatPacket()
                            packet.message = "{}: {}".format(minecraft_username, message_to_send)
                            self.connection.write_packet(packet)
                    else:
                        send_channel = message.channel
                        try:
                            if isinstance(message.channel, discord.abc.GuildChannel):
                                dm_channel = message.author.dm_channel
                                if not dm_channel:
                                    await message.author.create_dm()
                                send_channel = message.author.dm_channel
                            msg = "Unable to send chat message: there is no Minecraft account linked to this discord " \
                                "account, please run `mc!register`."
                            await send_channel.send(msg)
                        except discord.errors.Forbidden:
                            if isinstance(message.author, discord.abc.User):
                                msg = "{}, please allow private messages from this bot.".format(message.author.mention)
                                error_msg = await message.channel.send(msg)
                                await asyncio.sleep(3)
                                await error_msg.delete()
                            return
                        finally:
                            session.close()
                            del session
                else:
                    session.close()
                    del session

    def run(self):
        reactor_thread = Thread(target=self.run_auth_server, args=(self.config.auth_port,))
        reactor_thread.start()

        self.logger.debug("Checking if the server {} is online before connecting.")

        if not self.config.mc_online:
            self.logger.info("Connecting in offline mode...")
            while not self.is_server_online():
                self.logger.info('Not connecting to server because it appears to be offline.')
                time.sleep(15)
            self.bot_username = self.config.mc_username
            self.connection = Connection(
                self.config.mc_server, self.config.mc_port, username=self.config.mc_username,
                handle_exception=self.minecraft_handle_exception)
        else:
            self.auth_token = authentication.AuthenticationToken()
            try:
                self.auth_token.authenticate(self.config.mc_username, self.config.mc_password)
            except YggdrasilError as ex:
                self.logger.info(ex)
                sys.exit()
            self.bot_username = self.auth_token.profile.name
            self.logger.info("Logged in as %s...", self.auth_token.profile.name)
            while not self.is_server_online():
                self.logger.info('Not connecting to server because it appears to be offline.')
                time.sleep(15)
            self.connection = Connection(
                self.config.mc_server, self.config.mc_port, auth_token=self.auth_token,
                handle_exception=self.minecraft_handle_exception)

        self.register_handlers(self.connection)
        self.connection.connect()
        self.discord_bot.run(self.config.discord_token)

    def mc_uuid_to_username(self, mc_uuid: str):
        if mc_uuid not in self.uuid_cache:
            try:
                short_uuid = mc_uuid.replace("-", "")
                mojang_response = requests.get("https://api.mojang.com/user/profiles/{}/names".format(
                    short_uuid)).json()
                if len(mojang_response) > 1:
                    # Multiple name changes
                    player_username = mojang_response[-1]["name"]
                else:
                    # Only one name
                    player_username = mojang_response[0]["name"]
                self.uuid_cache[mc_uuid] = player_username
                return player_username
            except requests.RequestException as ex:
                self.logger.error(ex, exc_info=True)
                self.logger.error("Failed to lookup %s's username using the Mojang API.", mc_uuid)
        else:
            return self.uuid_cache[mc_uuid]

    def mc_username_to_uuid(self, username: str):
        if username not in self.uuid_cache.inv:
            try:
                player_uuid = requests.get(
                    "https://api.mojang.com/users/profiles/minecraft/{}".format(username)).json()["id"]
                long_uuid = uuid.UUID(player_uuid)
                self.uuid_cache.inv[username] = str(long_uuid)
                return player_uuid
            except requests.RequestException:
                self.logger.error("Failed to lookup %s's username using the Mojang API.", username)
        else:
            return self.uuid_cache.inv[username]

    def get_discord_help_string(self):
        help_str = ("Admin commands:\n"
                    "`mc!chathere`: Starts outputting server messages in this channel\n"
                    "`mc!stopchathere`: Stops outputting server messages in this channel\n"
                    "User commands:\n"
                    "`mc!tab`: Sends you the content of the server's player/tab list\n"
                    "`mc!register`: Starts the minecraft account registration process\n"
                    "To start chatting on the minecraft server, please register your account using `mc!register`.")
        return help_str

    # https://stackoverflow.com/questions/33404752/removing-emojis-from-a-string-in-python
    def remove_emoji(self, dirty_string):
        emoji_pattern = re.compile(
            "["
            u"\U0001F600-\U0001F64F"  # emoticons
            u"\U0001F300-\U0001F5FF"  # symbols & pictographs
            u"\U0001F680-\U0001F6FF"  # transport & map symbols
            u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
            u"\U0001F900-\U0001FAFF"  # CJK Compatibility Ideographs
            # u"\U00002702-\U000027B0"
            # u"\U000024C2-\U0001F251"
            "]+", flags=re.UNICODE)
        return emoji_pattern.sub(r'', dirty_string)

    def escape_markdown(self, md_string):
        # Absolutely needs to go first or it will replace our escaping slashes!
        escaped_string = md_string.replace("\\", "\\\\")
        escaped_string = escaped_string.replace("_", "\\_")
        escaped_string = escaped_string.replace("*", "\\*")
        return escaped_string

    def strip_colour(self, dirty_string):
        colour_pattern = re.compile(
            u"\U000000A7"  # selection symbol
            ".", flags=re.UNICODE)
        return colour_pattern.sub(r'', dirty_string)

    def setup_logging(self, level):
        if level.lower() == "debug":
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        log_format = "%(asctime)s:%(name)s:%(levelname)s:%(message)s"
        logging.basicConfig(filename="bridge_log.log", format=log_format, level=log_level)
        stdout_logger = logging.StreamHandler(sys.stdout)
        stdout_logger.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(stdout_logger)

    def run_auth_server(self, port):
        # We need to import twisted after setting up the logger because twisted hijacks our logging
        from twisted.internet import reactor
        from .auth_server import AuthFactory

        # Create factory
        factory = AuthFactory()

        # Listen
        self.logger.info("Starting authentication server on port %d", port)

        factory.listen("", port)
        try:
            reactor.run(installSignalHandlers=False)
        except KeyboardInterrupt:
            reactor.stop()

    def generate_random_auth_token(self, length):
        letters = string.ascii_lowercase + string.digits + string.ascii_uppercase
        return ''.join(random.choice(letters) for i in range(length))

    def handle_disconnect(self, json_data=""):
        self.logger.info('Disconnected.')
        if json_data:
            self.logger.info("Disconnect json data: %s", json_data)
        self.previous_player_list = self.player_list.copy()
        self.accept_join_events = False
        self.player_list = bidict()
        if self.connection.connected:
            self.logger.info("Forced a disconnection because the connection is still connected.")
            self.connection.disconnect(immediate=True)
        time.sleep(15)
        while not self.is_server_online():
            self.logger.info('Not reconnecting to server because it appears to be offline.')
            time.sleep(15)
        self.logger.info('Reconnecting.')
        self.connection.connect()

    def handle_disconnect_packet(self, disconnect_packet):
        self.handle_disconnect(disconnect_packet.json_data)

    def minecraft_handle_exception(self, exception, exc_info):
        self.logger.error("A minecraft exception occured! %s:", exception, exc_info=exc_info)
        self.handle_disconnect()

    def is_server_online(self):
        server = MinecraftServer.lookup("{}:{}".format(self.config.mc_server, self.config.mc_port))
        try:
            status = server.status()
            del status
            return True
        except ConnectionRefusedError:
            return False
        # AttributeError: 'TCPSocketConnection' object has no attribute 'socket'
        # This might not be required as it happens upstream
        except AttributeError:
            return False

    def register_handlers(self, connection):
        connection.register_packet_listener(
            self.handle_join_game, clientbound.play.JoinGamePacket)

        connection.register_packet_listener(
            self.handle_chat, clientbound.play.ChatMessagePacket)

        connection.register_packet_listener(
            self.handle_health_update, clientbound.play.UpdateHealthPacket)

        connection.register_packet_listener(
            self.handle_disconnect_packet, clientbound.play.DisconnectPacket)

        connection.register_packet_listener(
            self.handle_tab_list, clientbound.play.PlayerListItemPacket)

        connection.register_packet_listener(
            self.handle_player_list_header_and_footer_update, clientbound.play.PlayerListHeaderAndFooterPacket)

    def handle_player_list_header_and_footer_update(self, header_footer_packet):
        self.logger.debug("Got Tablist H/F Update: header=%s", header_footer_packet.header)
        self.logger.debug("Got Tablist H/F Update: footer=%s", header_footer_packet.footer)
        self.tab_header = json.loads(header_footer_packet.header)["text"]
        self.tab_footer = json.loads(header_footer_packet.footer)["text"]

    def handle_tab_list(self, tab_list_packet):
        self.logger.debug("Processing tab list packet")
        for action in tab_list_packet.actions:
            if isinstance(action, clientbound.play.PlayerListItemPacket.AddPlayerAction):
                self.logger.debug(
                    "Processing AddPlayerAction tab list packet, name: %s, uuid: %s", action.name, action.uuid)
                username = action.name
                player_uuid = action.uuid
                if action.name not in self.player_list.inv:
                    self.player_list.inv[action.name] = action.uuid
                else:
                    # Sometimes we get a duplicate add packet on join idk why
                    return
                if action.name not in self.uuid_cache.inv:
                    self.uuid_cache.inv[action.name] = action.uuid
                # Initial tablist backfill
                if self.accept_join_events:
                    webhook_payload = {
                        'username': username,
                        'avatar_url': "https://visage.surgeplay.com/face/160/{}".format(player_uuid),
                        'content': '',
                        'embeds': [{'color': 65280, 'title': '**Joined the game**'}]
                    }
                    for webhook in self.webhooks:
                        requests.post(webhook, json=webhook_payload)
                    if self.config.es_enabled:
                        self.es_logger.log_connection(
                            uuid=action.uuid, reason=ConnectionReason.CONNECTED, count=len(self.player_list))
                    return
                else:
                    # The bot's name is sent last after the initial back-fill
                    if action.name == self.bot_username:
                        self.accept_join_events = True
                        if self.config.es_enabled:
                            diff = set(self.previous_player_list.keys()) - set(self.player_list.keys())
                            for idx, player_uuid in enumerate(diff):
                                self.es_logger.log_connection(
                                    uuid=player_uuid, reason=ConnectionReason.DISCONNECTED,
                                    count=len(self.previous_player_list) - (idx + 1))
                        # Don't bother announcing the bot's own join message (who cares) but log it for analytics still
                        if self.config.es_enabled:
                            self.es_logger.log_connection(
                                uuid=action.uuid, reason=ConnectionReason.CONNECTED, count=len(self.player_list))

                if self.config.es_enabled:
                    self.es_logger.log_connection(uuid=action.uuid, reason=ConnectionReason.SEEN)
            if isinstance(action, clientbound.play.PlayerListItemPacket.RemovePlayerAction):
                self.logger.debug("Processing RemovePlayerAction tab list packet, uuid: %s", action.uuid)
                username = self.mc_uuid_to_username(action.uuid)
                player_uuid = action.uuid
                webhook_payload = {
                    'username': username,
                    'avatar_url': "https://visage.surgeplay.com/face/160/{}".format(player_uuid),
                    'content': '',
                    'embeds': [{'color': 16711680, 'title': '**Left the game**'}]
                }
                for webhook in self.webhooks:
                    requests.post(webhook, json=webhook_payload)
                del self.uuid_cache[action.uuid]
                del self.player_list[action.uuid]
                if self.config.es_enabled:
                    self.es_logger.log_connection(
                        uuid=action.uuid, reason=ConnectionReason.DISCONNECTED, count=len(self.player_list))

    def handle_join_game(self, join_game_packet):
        self.logger.info('Connected and joined game as entity id %d', join_game_packet.entity_id)
        self.player_list = bidict()

    def handle_chat(self, chat_packet):
        json_data = json.loads(chat_packet.json_data)
        if "extra" not in json_data:
            return
        chat_string = ""
        for chat_component in json_data["extra"]:
            chat_string += chat_component["text"]

        # Handle chat message
        regexp_match = re.match("<(.*?)> (.*)", chat_string, re.M | re.I)
        if regexp_match:
            username = regexp_match.group(1)
            original_message = regexp_match.group(2)
            player_uuid = self.mc_username_to_uuid(username)
            if username.lower() == self.bot_username.lower():
                # Don't relay our own messages
                if self.config.es_enabled:
                    bot_message_match = re.match("<{}> (.*?): (.*)".format(
                        self.bot_username.lower()), chat_string, re.M | re.I)
                    if bot_message_match:
                        self.es_logger.log_chat_message(
                            uuid=self.mc_username_to_uuid(bot_message_match.group(1)),
                            display_name=bot_message_match.group(1),
                            message=bot_message_match.group(2),
                            message_unformatted=chat_string)
                        self.es_logger.log_raw_message(
                            msg_type=chat_packet.Position.name_from_value(chat_packet.position),
                            message=chat_packet.json_data)
                return
            self.logger.info("Incoming message from minecraft: Username: %s Message: %s", username, original_message)
            self.logger.debug("msg: %s", repr(original_message))
            message = self.escape_markdown(self.remove_emoji(original_message.strip().replace(
                "@", "@\N{zero width space}")))
            webhook_payload = {
                'username': username,
                'avatar_url': "https://visage.surgeplay.com/face/160/{}".format(player_uuid),
                'content': '{}'.format(message)
            }
            for webhook in self.webhooks:
                requests.post(webhook, json=webhook_payload)
            if self.config.es_enabled:
                self.es_logger.log_chat_message(
                    uuid=player_uuid, display_name=username, message=original_message, message_unformatted=chat_string)
        if self.config.es_enabled:
            self.es_logger.log_raw_message(
                msg_type=chat_packet.Position.name_from_value(chat_packet.position),
                message=chat_packet.json_data)

    def handle_health_update(self, health_update_packet):
        if health_update_packet.health <= 0:
            self.logger.debug("Respawned the player because it died")
            packet = serverbound.play.ClientStatusPacket()
            packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
            self.connection.write_packet(packet)


def main():
    bridge = MinecraftDiscordBridge()
    bridge.run()


if __name__ == "__main__":
    main()
