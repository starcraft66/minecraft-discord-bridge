from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

_engine = None
Base = declarative_base()

def initialize(config):
    global _engine
    _connection_string = config.database_connection_string
    _engine = create_engine(_connection_string)
    Base.metadata.create_all(_engine)

def get_session():
    Session = sessionmaker(bind=_engine)()
    return Session