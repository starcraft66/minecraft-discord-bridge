FROM python:3.6.6-stretch

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir pipenv \
    && python -m pipenv --three \
    && python -m pipenv install

VOLUME "/data"

CMD [ "python", "-m", "pipenv", "run", "./webhook-bridge.py" ]