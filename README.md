![](https://github.com/starcraft66/minecraft-discord-bridge/workflows/Docker%20Image/badge.svg)
![](https://img.shields.io/docker/pulls/starcraft66/minecraft-discord-bridge)
# Minecraft Discord Bridge
Required Python version: 3.5 or later.

Docker is not required to run this bot but its use is strongly encouraged for ease of management.

## Installation instructions
1. Clone the repository.
2. Edit the config.json file to your liking, an example is provided in `config.example.json`.

     ```
    mv config.example.json config.json
    vi config.json
     ```

3. If you are using an sqlite database (like the default one in the config, create it now).
 
    ```
    touch db.sqlite
    ```

4. Run the bridge!
    1. If you are not using docker, just install the dependencies and start the bot.
    
        ```
        python -m pipenv --three
        python -m pipenv install
        python -m pipenv run python -m minecraft_discord_bridge
        ```
    
    2. You may optionally specify a custom path to the json configuration file using the `--config-file` or `-f` command-line options. E.g. `python -m pipenv run python -m minecraft_discord_bridge -f /path/to/custom/config`.
        
    3. If you are using docker, just use the included `docker-compose.yml` to get up and running.
    
        ```
        docker-compose up -d
        ```
        
5. If this is the first time you run this bridge, you need to invite it to your discord guild.
 
    A log message containing the invite link will be printed out every time the bridge is started. Launch the bridge and click the link in the log and follow the prompts on discord's website to add the bridge's bot to your guild.
     
    Once it has joined your server, create a text channel for it to post in, then press the "Edit Channel" button on that channel. From there, press the "Permissions" button and click the "+" button and add "Minecraft Chat Bridge" to the room and close the permissions window.
     
    Now that permissions are set, all you need to do is to do is to type "mc!chathere" and the bridge will take over if it is running.
     
## Creating a discord bot and getting its discord token

1. Head over to the [discord developer portal](https://discordapp.com/developers/applications) and sign in if you haven't already.

2. Press "Create an application". Once you do so, you may give the application a name and an icon if desired.

3. From the left menu, click "Bot", then press "Add bot" on the next screen and "Yes do it" on the popup that appears.

4. From here, you can once again give the Bot account your desired username and profile picture.

5. Finally, Press the "Copy" button under the "Token" section to get your discord bot token. You can now paste it into this bridge's `config.json` file.

## Creating the wildcard DNS record

This step can be achieved in a variety of ways but I will cover basic steps for setting this up using the cloudflare DNS servers.

1. [Create an account and add your domain to cloudflare](https://support.cloudflare.com/hc/en-us/articles/201720164-Step-2-Create-a-Cloudflare-account-and-add-a-website)

2. From the cloudflare dashboard, click on your site and then click on the blue "DNS" icon at the top of the dashboard.

3. From the DNS records section, select "A" in the dropdown, type any name you want in the "name" field and type in your computer's public IPv4 address into the "IPv4 address" field, then click on the orange cloud icon until it becomes gray and press the "Add Record" button. **Note:** If your computer is behind a NAT gateway, you will need to "port forward" the port specified in the `AUTH_SERVER.PORT` inside `config.json` to your computer's private IPv4 address.

4. Repeat this process but choose "CNAME" from the dropdown, then type `*.authentication` (or anything you want as long as it starts with `*.`) and type whatever name you chose in step 3 into the "Domain name" box. Click on the orange cloud icon until it becomes gray and press the "Add Record" button.

5. Set the `AUTH_SERVER.DNS_WILDCARD` node in `config.json` to the name you chose in step 4 (but without the `*.` part!!!) and append `.yourdomain.tld` to it where `yourdomain.tld` is the name of your domain. **e.g.** *For the record `*.authentication` on domain `example.com`, you would write `authentication.example.com`.*

## Configuration
All of the configuration data is stored in a file called `config.json` that must be stored in the same directory as the executable

## Local development environment
To facilitate development, a docker-based local development environment that spins up a minecraft server and a copy of the bridge from local repository source code is provided.

To use it, simply copy `config.development.example.json` to `config.development.json` and fill in your discord application token and/or change any other relevant settings, then run `./scripts/development-environment.sh`.

A local offline-mode minecraft server and bridge will be started up and connect automatically. You can then connect a local minecraft client to the server by connecting to `localhost:25565`.

The authenication server is also reachable at `localhost:9822` with the dns wildcard `localhost4.tdude.co` because I configured `*.localhost4.tdude.co` to resolve to `127.0.0.1`.

Additionally, the python code running inside the container can be remotely debugged in compatible IDEs via a server speaking the Debug Adapter Protocol available at `localhost:5678`.

**Note:** Since the development minecraft server runs in offline mode, UUIDs of players will differ from their real UUID returned by the Mojang API and this may cause exceptions related to the UUID cache. This is currently a known issue and may be fixed in the future.

The development docker image can be rebuilt by running `./scripts/development-environment.sh -r` if python dependencies need to be changed or for any other reason.

#### Json keys
|Key                        |Default value              |Explanation|
|:--------------------------|:--------------------------|:----------|
|MAIN.MC_USERNAME           |""                         |The username or e-mail address of the bot's minecraft account
|MAIN.MC_PASSWORD           |""                         |The password of the bot's minecraft account
|MAIN.MC_SERVER             |""                         |The IPv4 address of the minecraft server to connect to
|MAIN.MC_PORT               |25565                      |The port of the minecraft server to connect to
|MAIN.MC_ONLINE             |true                       |Whether or not to authenticate the bot's minecraft account with Mojang's authentications server
|MAIN.DISCORD_APP_TOKEN     |""                         |The discord bot token the birdge will use to log into discord
|MAIN.LOG_LEVEL             |"INFO"                     |Set the log level, can be `INFO` or `DEBUG`
|MAIN.MESSAGE_DELAY         |1.5                        |Set the delay between messages sent from discord to minecraft
|MAIN.FAILSAFE_RETRIES      |3                          |The amount of times to try reconnecting to an online server before giving up and exiting.
|MAIN.VANILLA_CHAT_MODE     |false                      |Whether to parse chat using the vanilla server chat format or not (required on vanilla servers)
|MAIN.ADMINS                |\[283983554051047425\]     |Array of discord user ids that have administrative access to the bot
|AUTH_SERVER.BIND_IP        |""                         |The IPv4 address which the authentication server will bind to (set to blank for 0.0.0.0)
|AUTH_SERVER.PORT           |9822                       |The port which the authentication server will bind to
|AUTH_SERVER.DNS_WILDCARD   |""                         |Must be set to a wildcard DNS `CNAME` record that points to an `A` record pointing to the authentication server's IP address
|DATABASE.CONNECTION_STRING |"sqlite:////data/db.sqlite"|Must be set to any valid `SQLAlchemy` connection string. Defaults to an empty sqlite database in `/data` for docker users
|ELASTICSEARCH.ENABLED      |false                      |Whether or not to enable elasticsearch analytics collection
|ELASTICSEARCH.URL          |""                         |Fully qualified URL to the elasticsearch server
|ELASTICSEARCH.AUTH         |false                      |Whether or not the elasticsearch http endpoint is protected by HTTP Basic authentication
|ELASTICSEARCH.USERNAME     |""                         |HTTP Basic authentication username for elasticsearch
|ELASTICSEARCH.PASSWORD     |""                         |HTTP Basic authentication password for elasticsearch
|DEBUGGING.ENABLED          |false                      |Whether or not to enable remote python debugging
|DEBUGGING.BIND_IP          |"0.0.0.0"                  |The IP address which the remote debugging server will bind to
|DEBUGGING.PORT             |5678                       |The port which the remote debugging server will bind to
