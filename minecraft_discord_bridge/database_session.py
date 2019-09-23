from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class DatabaseSession():
    def __init__(self):
        self._engine = None
        self.connection_string = None

    def initialize(self, config):
        self.connection_string = config.database_connection_string
        self._engine = create_engine(self.connection_string)
        Base.metadata.create_all(self._engine)

    def get_session(self):
        session = sessionmaker(bind=self._engine)()
        return session
