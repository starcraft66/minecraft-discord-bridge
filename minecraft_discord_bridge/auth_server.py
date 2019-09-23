from datetime import datetime

from quarry.net.server import ServerFactory, ServerProtocol

from .database import AccountLinkToken, MinecraftAccount, DiscordAccount

DATABASE_SESSION = None


class AuthProtocol(ServerProtocol):
    def player_joined(self):
        # This method gets called when a player successfully joins the server.
        #   If we're in online mode (the default), this means auth with the
        #   session server was successful and the user definitely owns the
        #   display name they claim to.

        # Call super. This switches us to "play" mode, marks the player as
        #   in-game, and does some logging.
        ServerProtocol.player_joined(self)

        # Define your own logic here. It could be an HTTP request to an API,
        #   or perhaps an update to a database table.
        display_name = self.display_name
        uuid = self.uuid

        # Monkey Patch for Forge deciding to append "\x00FML\x00" to the connection string
        if self.connect_host.endswith("\x00FML\x00"):
            ip_addr = self.connect_host[:-5]
        else:
            ip_addr = self.connect_host

        connect_port = self.connect_port

        self.logger.info("[AUTH SERVER] %s (%s) connected to address %s:%s",
                         display_name, uuid, ip_addr, connect_port)

        connection_token = ip_addr.split(".")[0]
        session = DATABASE_SESSION.get_session()
        token = session.query(AccountLinkToken).filter_by(token=connection_token).first()
        if not token:
            self.close("You have connected with an invalid token!")
            session.close()
            return
        discord_account = session.query(DiscordAccount).filter_by(link_token_id=token.id).first()
        if not discord_account:
            self.close("You have connected with an invalid token!")
            session.close()
            return
        if datetime.utcnow() < token.expiry:
            # Check if they already have a linked account and are re-linking
            if discord_account.minecraft_account_id is not None:
                existing_account = session.query(MinecraftAccount).filter_by(
                    id=discord_account.minecraft_account_id).first()
                self.logger.info("unlinking existing %s account and replacing it with %s",
                                 existing_account.minecraft_uuid, str(uuid))
                session.delete(existing_account)
            mc_account = MinecraftAccount(str(uuid), discord_account.id)
            discord_account.minecraft_account = mc_account
            session.add(mc_account)
            session.delete(token)
            session.commit()
            session.close()
            self.close("Your minecraft account has successfully been linked to your discord account!")
            return
        else:
            session.delete(token)
            session.commit()
            session.close()
            self.close("You have connected with an expired token! "
                       "Please run the mc!register command again to get a new token.")
            return

        # Kick the player.
        self.close("This shouldn't happen!")


class AuthFactory(ServerFactory):
    protocol = AuthProtocol
    motd = "Auth Server"
