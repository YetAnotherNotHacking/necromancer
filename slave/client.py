# Storagemanager client

import requests
import os
import json
import time
from pathlib import Path
from colorama import Fore, Style, init
from datetime import datetime
from tqdm import tqdm
import shutil


debug = False

# Splash and other prog vars
version = "0.2.2beta"
company = "Silverflag"
systemname = "Necromancer"
debug = False
logo = [
"███▄    █ ▓█████  ▄████▄   ██▀███   ▒█████   ███▄ ▄███▓ ▄▄▄       ███▄    █  ▄████▄  ▓█████  ██▀███",
"██ ▀█   █ ▓█   ▀ ▒██▀ ▀█  ▓██ ▒ ██▒▒██▒  ██▒▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ ▒██▀ ▀█  ▓█   ▀ ▓██ ▒ ██▒",
"▓██  ▀█ ██▒▒███   ▒▓█    ▄ ▓██ ░▄█ ▒▒██░  ██▒▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒▒▓█    ▄ ▒███   ▓██ ░▄█ ▒",
"▓██▒  ▐▌██▒▒▓█  ▄ ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒██   ██░▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒▒▓▓▄ ▄██▒▒▓█  ▄ ▒██▀▀█▄",
"▒██░   ▓██░░▒████▒▒ ▓███▀ ░░██▓ ▒██▒░ ████▓▒░▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░▒ ▓███▀ ░░▒████▒░██▓ ▒██▒",
"░ ▒░   ▒ ▒ ░░ ▒░ ░░ ░▒ ▒  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ░▒ ▒  ░░░ ▒░ ░░ ▒▓ ░▒▓░",
"░ ░░   ░ ▒░ ░ ░  ░  ░  ▒     ░▒ ░ ▒░  ░ ▒ ▒░ ░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░  ░  ▒    ░ ░  ░  ░▒ ░ ▒░",
"   ░   ░ ░    ░   ░          ░░   ░ ░ ░ ░ ▒  ░      ░     ░   ▒      ░   ░ ░ ░           ░     ░░   ░",
"         ░    ░  ░░ ░         ░         ░ ░         ░         ░  ░         ░ ░ ░         ░  ░   ░",
"                  ░                                                          ░"
]

print(f"{company} {systemname} v{version}")
# do color gradients
start = (0, 200, 255)
end = (255, 0, 100)
steps = len(logo)

# find mix values
def mix(a, b, t):
    return int(a + (b - a) * t)

# print and mix
for i, line in enumerate(logo):
    t = i / max(steps - 1, 1)
    r = mix(start[0], end[0], t)
    g = mix(start[1], end[1], t)
    b = mix(start[2], end[2], t)
    print(f"\033[38;2;{r};{g};{b}m{line}\033[0m")

class logfw:
    class Logger:
        LEVELS = {
            'INFO': Fore.CYAN,
            'WARN': Fore.YELLOW,
            'ERROR': Fore.RED,
            'SUCCESS': Fore.GREEN,
            'DEBUG': Fore.MAGENTA
        }

        def __init__(self, name=None):
            self.name = name or 'LOG'

        def _log(self, level, msg):
            color = self.LEVELS.get(level, Fore.WHITE)
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{Style.BRIGHT}{Fore.WHITE}[{timestamp}] {color}[{level:<7}] {Fore.WHITE}{self.name}: {msg}")

        def info(self, msg):
            self._log('INFO', msg)
        def warn(self, msg):
            self._log('WARN', msg)
        def error(self, msg):
            self._log('ERROR', msg)
        def success(self, msg):
            self._log('SUCCESS', msg)
        def debug(self, msg):
            if debug == True:
                self._log('DEBUG', msg)
            else:
                pass

log = logfw.Logger(systemname)
log.info("Hello from StorageManager")

def write_client_config(configpath, server_url, username, server_root, local_root, sync_interval):
    data = {
        "server_url": server_url,
        "username": username,
        "server_root": str(server_root),
        "local_root": str(local_root),
        "sync_interval": sync_interval
    }
    configpath = Path(configpath)
    configpath.parent.mkdir(parents=True, exist_ok=True)
    with configpath.open("w") as f:
        json.dump(data, f, indent=4)
    log.info(f"Wrote config to {configpath}")

def read_client_config(configpath):
    configpath = Path(configpath)
    with configpath.open() as f:
        data = json.load(f)
    return data

class ClientAuth:
    def __init__(self, server_url, token_file="token.txt"):
        self.server_url = server_url
        self.token_file = token_file
        self.token = None
        self.load_token()

    # load a saved token
    def load_token(self):
        try:
            with open(self.token_file, 'r') as f:
                self.token = f.read().strip()
                log.info("Loaded token from cache file")
        except FileNotFoundError:
            log.warn("Token file does not exist")
    
    # save token to a file
    def save_token(self):
        with open(self.token_file, 'w') as f:
            f.write(self.token)
        log.success("Wrote token to file.")
    
    # ask server for a token
    def login(self, username, password):
        try:
            response = requests.post(
                f"{self.server_url}/auth/login",
                json={"username": username, "password": password}
            )
            if response.status_code == 200:
                self.token = response.json()['token']
                self.save_token()
                log.success("Login successful")
                return True
            else:
                log.error(f"Login failed: {response.json().get('error', 'Unknown error')}")
                return False
        except Exception as e:
            log.error(f"Login error: {e}")
            return False
    
    def logout(self):
        try:
            response = requests.post(
                f"{self.server_url}/auth/logout",
                json={"token": self.token}
            )
            if response.status_code == 200:
                self.token = None
                if os.path.exists(self.token_file):
                    os.remove(self.token_file)
                log.success("Loggged out.")
                return True
        except Exception as e:
            log.error(f"Logout error: {e}")
        return False
    # get headers to perform requests to the necromancer instance
    def get_headers(self):
        if not self.token:
            log.error("No token available. Please login first.")
            return None
        return {"Authorization": self.token}

class ClientSync:
    def __init__(self, server_url, auth):
        self.server_url = server_url
        self.auth = auth
    
    # file hash manager function
    def verify_file_hash(path, chunk_size=4<<20):
        try:
            import xxhash
            log.debug("Hashing with xxhash")
            return xxhash.xxh64(open(path, 'rb').read()).hexdigest()
        except Exception:
            log.warn("Slow hashing is used, install python package \'xxhash\' to resolve this issue.")
            import zlib
            return format(zlib.crc32(open(path, "rb").read()) & 0xFFFFFFFF, "08x")

    def download_manifest(self):
        headers = self.auth.get_headers()
        if not headers:
            return None
        
        try:
            log.info("Downloading manifest from server...")
            response = requests.get(
                f"{self.server_url}/sync/manifest",
                headers=headers
            )
            if response.status_code == 200:
                manifest = response.json()['manifest']
                log.success(f"Downloaded manifest with {len(manifest)} files")
                return manifest
            else:
                log.error(f"Failed to download manifest: {response.json().get('error', 'Unknown error')}")
                return None
        except Exception as e:
            log.error(f"Manifest download error: {e}")
            return None

    # compare remote and local manifest to see what diffs need syncing
    def compare_manifests(server_manifest, local_files, local_root, server_root):
        files_to_download = []
        files_to_delete = []

        # convert them into a dict (easier lookups)
        server_dict = {}
        for item in server_manifest:
            server_path = item['path']
            # strip server root to get relative path
            if server_root and server_path.startswith(server_root):
                relative_path = os.path.relpath(server_path, server_root)
            else:
                relative_path = server_path
            server_dict[relative_path] = item

        for relative_path, server_info in server_dict.items():
            normalized_path = os.path.normpath(relative_path)
            if normalized_path not in local_files:
                log.debug(f"New file: {normalized_path}")
                files_to_download.append(server_info)
            else:
                local_info = local_files[normalized_path]
                if local_info['hash'] != server_info['hash']:
                    # file hash missmatch, sync it
                    log.debug(f"Modified file: {normalized_path}")
                    files_to_download.append(server_info)

        for local_path in local_files:
            if local_path not in server_dict:
                log.debug(f"Found file that is now excess, as server no longer reports it: {local_path}")
                files_to_delete.append(local_path)

        log.info(f"DIFFCHECK - Changed/created files: {len(files_to_download)}")
        log.info(f"DIFFCHECK - Purged files: {len(files_to_delete)}")

        return files_to_download, files_to_delete

    def scan_local_files(local_root):
        local_files = {}
        log.info(f"Scanning local files in {local_root}")

        for root, dirs, files in os.walk(local_root):
            for filename in files:
                full_path = os.path.join(root, filename)
                try:
                    file_hash = ClientSync.verify_file_hash(full_path)
                    rel_path = os.path.relpath(full_path, local_root)
                    local_files[rel_path] = {
                        'hash': file_hash,
                        'size': os.path.getsize(full_path),
                        'mtime': int(os.path.getmtime(full_path)),
                        'full_path': full_path
                    }
                except Exception as e:
                    log.warn(f"Failed to hash {full_path}: {e}")
        
        log.info(f"Found {len(local_files)} local files")
        return local_files

    def download_file(self, file_path, local_root, server_root):
        headers = self.auth.get_headers()
        if not headers:
            return False
        
        try:
            # strip server root to get relative path
            if server_root and file_path.startswith(server_root):
                relative_path = os.path.relpath(file_path, server_root)
            else:
                relative_path = file_path
            
            response = requests.get(
                f"{self.server_url}/sync/file",
                headers=headers,
                params={"path": file_path},
                stream=True
            )
            
            if response.status_code == 200:
                # use relative path for local storage
                local_path = os.path.join(local_root, relative_path)
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                
                # get file size for progress bar
                total_size = int(response.headers.get('content-length', 0))
                                
                # truncate filename if too long for display
                display_name = relative_path if len(relative_path) <= 40 else '...' + relative_path[-37:]
                term_width = shutil.get_terminal_size().columns
                with open(local_path, 'wb') as f:
                    with tqdm(
                        total=total_size,
                        unit='B',
                        unit_scale=True,
                        unit_divisor=1024,
                        desc=f"{Fore.CYAN}{display_name}{Style.RESET_ALL}",
                        bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]',
                        ncols=term_width,  # Use terminal width
                        colour='cyan'
                    ) as pbar:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                            pbar.update(len(chunk))
                    
                log.debug(f"Downloaded: {relative_path}")
                return True
            else:
                log.error(f"Failed to download {file_path}: {response.status_code}")
                return False
        
        except Exception as e:
            log.error(f"Download returned an error for {file_path}: {e}")
            return False

class storage_client:
    def __init__(self, config_path="client_config.json"):
        self.config_path = config_path
        self.config = None
        self.auth = None
        self.sync = None
    
    def initall(self):
        # initialize client with config
        if not os.path.exists(self.config_path):
            log.error(f"Config file not found: {self.config_path}")
            return False
        
        self.config = read_client_config(self.config_path)
        self.auth = ClientAuth(
            self.config['server_url'],
            token_file="client_token.txt"
        )
        self.sync = ClientSync(self.config['server_url'], self.auth)
        
        return True
    
    def login(self, username=None, password=None):
        # login to server
        username = username or self.config.get('username')
        if not password:
            from getpass import getpass
            password = getpass("Password: ")
        
        return self.auth.login(username, password)
    
    def perform_sync(self):
        # perform a full sync operation
        log.info("=== Starting Sync ===")
        
        # download server manifest
        server_manifest = self.sync.download_manifest()
        if not server_manifest:
            log.error("Failed to get server manifest")
            return False
        
        # scan local files
        local_root = self.config['local_root']
        server_root = self.config.get('server_root', '')
        local_files = ClientSync.scan_local_files(local_root)
        
        # compare and find differences
        files_to_download, files_to_delete = ClientSync.compare_manifests(
            server_manifest, local_files, local_root, server_root
        )
        if not files_to_download:
            log.success("Everything is up to date!")
            return True
        
        # download changed files with overall progress
        log.info(f"Beginning download of {len(files_to_download)} files...")
        print()  # spacing
        
        success_count = 0
        failed_files = []
        
        term_width = shutil.get_terminal_size().columns

        # overall progress bar
        with tqdm(
            total=len(files_to_download),
            desc=f"{Fore.GREEN}Overall Progress{Style.RESET_ALL}",
            unit='file',
            position=0,
            leave=True,
            colour='green',
            ncols=term_width,  # Use terminal width
            bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} files [{elapsed}<{remaining}]'
        ) as overall_pbar:
            for file_info in files_to_download:
                if self.sync.download_file(file_info['path'], local_root, server_root):
                    success_count += 1
                else:
                    failed_files.append(file_info['path'])
                overall_pbar.update(1)
        
        print()  # spacing
        log.success(f"Successfully downloaded {success_count}/{len(files_to_download)} files")
        
        if failed_files:
            log.warn(f"Failed to download {len(failed_files)} files:")
            for failed in failed_files[:5]:  # show first 5 failures
                log.error(f"  - {failed}")
            if len(failed_files) > 5:
                log.error(f"  ... and {len(failed_files) - 5} more")
        
        log.info("=== Sync Complete ===")
        return success_count > 0
    
    def run_continuous(self):
        # run continuous sync loop
        sync_interval = self.config.get('sync_interval', 600)
        
        log.info(f"Starting continuous sync (interval: {sync_interval}s)")
        
        while True:
            try:
                self.perform_sync()
            except Exception as e:
                log.error(f"Sync error: {e}")
            
            log.info(f"Waiting {sync_interval} seconds until next sync...")
            time.sleep(sync_interval)

class interface:
    def confirmation_dialogue(question, default=True):
        if default == True:
            defanswer = "[Y/n]"
        else:
            defanswer = "[y/N]"
        userinput = input(f"{question} - {defanswer}")
        if (userinput.lower() == "y") or (userinput == "" and default == True):
            return True
        else:
            return False

    def ifbackend(mode):
        modes = ["init", "login", "sync", "run"]
        log.debug(f"Interface backend running in mode {mode}")
        
        if mode not in modes:
            log.error(f"Mode \'{mode}\' is not supported, supported options are {modes}")
            exit()

        client = storage_client()

        match mode:
            case "init":
                # create initial config
                log.info("Client configuration wizard")
                server_url = input("Server URL (e.g., http://192.168.1.100:5000): ")
                username = input("Username: ")
                server_root = input("Server root path (ask the host): ")
                local_root = input("Local directory to sync: ")
                sync_interval_input = input("Sync interval (seconds, default 600): ")
                sync_interval = int(sync_interval_input) if sync_interval_input else 600
                
                data = {
                    "server_url": server_url,
                    "username": username,
                    "server_root": server_root,
                    "local_root": str(local_root),
                    "sync_interval": sync_interval
                }
                configpath = Path("client_config.json")
                configpath.parent.mkdir(parents=True, exist_ok=True)
                with configpath.open("w") as f:
                    json.dump(data, f, indent=4)
                log.info(f"Wrote config to {configpath}")
                
                log.success("Client config created. Run 'storageclient login' next.")
            
            case "login":
                if client.initall():
                    username = input("Username: ").strip()
                    from getpass import getpass
                    password = getpass("Password: ")
                    client.login(username, password)
                else:
                    log.error("Failed to initialize client. Run 'storageclient init' first.")
            
            case "sync":
                if client.initall():
                    client.perform_sync()
                else:
                    log.error("Failed to initialize client. Run 'storageclient init' first.")
            
            case "run":
                if client.initall():
                    client.run_continuous()
                else:
                    log.error("Failed to initialize client. Run 'storageclient init' first.")

    def local_argument_parser():
        import argparse
        
        parser = argparse.ArgumentParser(description=f"{systemname} Client")
        parser.add_argument("runmode", help="Mode to run progam in, options: init, login, sync, run")
        
        inputargs = parser.parse_args()
        
        if inputargs.runmode:
            interface.ifbackend(inputargs.runmode)

if __name__ == "__main__":
    interface.local_argument_parser()