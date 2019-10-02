#
# Copyright (c) 2018 Tristan Gosselin-Hane.
#
# This file is part of minecraft-discord-bridge
# (see https://github.com/starcraft66/minecraft-discord-bridge).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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
