from sqlalchemy import Column, String, Integer, Date
from sqlalchemy.ext.declarative import declarative_base
from database_session import Base

class DiscordChannel(Base):
    __tablename__ = 'discord_channels'

    id = Column(Integer, primary_key=True)
    channel_id = Column(Integer)

    def __init__(self, channel_id):
        self.channel_id = channel_id