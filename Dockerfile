FROM python:3.9.0 AS builder

ENV PYTHONUNBUFFERED=0

WORKDIR /app

COPY Pipfile Pipfile.lock setup.py /app/
COPY minecraft_discord_bridge /app/minecraft_discord_bridge/

RUN pip install --no-cache-dir pipenv \
    && python -m pipenv --three \
    && python -m pipenv install

FROM python:3.9.0-slim AS runtime

ENV PYTHONUNBUFFERED=0

WORKDIR /app

COPY --from=builder /root/.local/share/virtualenvs /root/.local/share/virtualenvs
COPY --from=builder /app /app

RUN pip install --no-cache-dir pipenv

VOLUME "/data"

CMD [ "python", "-m", "pipenv", "run", "python", "-m", "minecraft_discord_bridge" ]
