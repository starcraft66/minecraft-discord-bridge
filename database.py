from datetime import datetime, timedelta, timezone

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from database_session import Base


class DiscordChannel(Base):
    __tablename__ = 'discord_channels'

    id = Column(Integer, primary_key=True)
    channel_id = Column(Integer)

    def __init__(self, channel_id):
        self.channel_id = channel_id


class AccountLinkToken(Base):
    __tablename__ = 'account_link_tokens'

    id = Column(Integer, primary_key=True)
    discord_account = relationship("DiscordAccount", back_populates="link_token")
    token = Column(String)
    expiry = Column(DateTime)

    def __init__(self, discord_id, token):
        self.discord_id = discord_id
        self.token = token
        now = datetime.now(timezone.utc)
        # Token expires an hour from now
        then = now + timedelta(hours=1)
        self.expiry = then


class MinecraftAccount(Base):
    __tablename__ = 'minecraft_accounts'

    id = Column(Integer, primary_key=True)
    minecraft_uuid = Column(String)
    discord_account = relationship("DiscordAccount", back_populates="minecraft_account")

    def __init__(self, minecraft_uuid, discord_id):
        self.minecraft_uuid = minecraft_uuid
        self.discord_account_id = discord_id


class DiscordAccount(Base):
    __tablename__ = 'discord_accounts'

    id = Column(Integer, primary_key=True)
    discord_id = Column(Integer)
    link_token_id = Column(Integer, ForeignKey('account_link_tokens.id'))
    minecraft_account_id = Column(Integer, ForeignKey('minecraft_accounts.id'))
    link_token = relationship(
        "AccountLinkToken", uselist=False, foreign_keys=[link_token_id], back_populates="discord_account")
    minecraft_account = relationship(
        "MinecraftAccount", uselist=False, foreign_keys=[minecraft_account_id], back_populates="discord_account")

    def __init__(self, discord_id):
        self.discord_id = discord_id
