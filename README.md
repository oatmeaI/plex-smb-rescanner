# Plex SMB Rescanner
> Trigger partial rescans of Plex libraries on SMB change notifications

If you're like me, and you have your Plex media hosted on an SMB share and Plex Media Server running on a different computer, 
you might have found that Plex Media Server isn't able to automatically rescan when media is added/changed/removed from your media folders.

This Python script connects to the SMB share, listens for change notifications, and triggers Plex Media Server to do a partial rescan on the changed folders - essentially restoring the default Plex functionality.

## Usage
1. Download or clone this repo
2. Install project requirements - [uv](https://github.com/astral-sh/uv) is recommended, but is not required.
3. Rename `config.toml.example` to `config.toml`
4. Update `config.toml` your SMB share details, Plex details, etc. Follow the comments in the file for hints.
5. Run `main.py`
