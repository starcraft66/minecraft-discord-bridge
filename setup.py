import setuptools
import minecraft_discord_bridge

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="minecraft-discord-bridge",
    version=minecraft_discord_bridge.__version__,
    author="Tristan Gosselin-Hane",
    author_email="starcraft66@gmail.com",
    description="A bridge between minecraft and discord chat",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/starcraft66/minecraft-discord-bridge",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
)
