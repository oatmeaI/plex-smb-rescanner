import os
import tomllib
import urllib.request
import urllib.parse
from threading import Timer


class Scheduler:
    timer = None
    scan_dirs = []

    library_path = ""
    ignore_paths = []
    section_map = {}
    rescan_actions = []
    plex_address = ""
    plex_token = ""

    def __init__(self):
        with open("./config.toml", "rb") as f:
            data = tomllib.load(f)

        self.library_path = data["library_path"]
        self.ignore_paths = data["ignore_paths"]
        self.section_map = data["section_map"]
        self.rescan_actions = data["rescan_actions"]
        self.plex_address = data["plex_address"]
        self.plex_token = data["plex_token"]

    def run_scan(self):
        print("Running queue")
        for dir in self.scan_dirs:
            print(f"Processing {dir}")

            section = None
            for k, v in self.section_map.items():
                if k in dir:
                    section = v

            if section is None:
                print(f"Skipping {dir} because it's not part of the Plex library\n")
                continue

            should_scan = True
            for other_dir in self.scan_dirs:
                if (
                    dir in other_dir
                    and dir != other_dir
                    and os.path.isdir(self.make_path(other_dir))
                ):
                    should_scan = False
                    print(f"Skipping {dir} because there's a more specific path\n")
                    break
            if not should_scan:
                continue

            qs = urllib.parse.urlencode(
                {"path": self.make_path(dir), "X-Plex-Token": self.plex_token}
            )
            url = f"{self.plex_address}/library/sections/{section}/refresh?{qs}"
            print(url)
            urllib.request.urlopen(url).read()
            print(f"Scanned {dir}\n")

        self.scan_dirs = []
        print("finished queue")

    def make_path(self, dir):
        return os.path.join(self.library_path, dir.replace("\\", "/"))

    def add_scan(self, dir, action):
        for path in self.ignore_paths:
            if path in dir:
                print(f"Ignoring {dir} because it was found in {path}\n")
                return

        if len(self.rescan_actions) > 0 and action not in self.rescan_actions:
            print(f"Ignoring {action}\n")
            return

        full_path = self.make_path(dir)
        if os.path.splitext(full_path)[-1] != "":
            print(f"Ignoring {full_path} because it is not a folder\n")
            return

        if dir in self.scan_dirs:
            print(f"Ignoring {dir} because it is already queued\n")
            return

        print(f"Queueing {dir}...")
        self.scan_dirs.append(dir)

        if self.timer is not None:
            self.timer.cancel()

        self.timer = Timer(10, self.run_scan)
        self.timer.start()
