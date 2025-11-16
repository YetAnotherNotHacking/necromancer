# Necromancer utility
# Sync minecraft servers over the internet to prevent outages

version = "0.1.1"
company = "Silverflag"
systemname = "Necromancer"
debug = False
logo = [
":::.    :::.",
"`;;;;,  `;;;",
"  [[[[[. '[[,cc[[[cc. ,cc[[[cc.=,,[[== ,ccc,  [ccc, ,cccc,  ,ccc,   [ccccc,  ,cc[[[cc. ,cc[[[cc.=,,[[==",
"  $$$ \"Y$c$$$$$___--' $$$      `$$$\"``$$$\"c$$$$$$$$$$$\"$$$ $$$cc$$$ $$$$\"$$$ $$$       $$$___--'`$$$\"``",
"  888    Y8888b    ,o,88b    ,o,888   888   88888 Y88\" 888o888   888888  Y88o88b    ,o,88b    ,o,888",
"  MMM     YM \"YUMMMMP\" \"YUMMMMP\"\"MM,   \"YUMMP MMM  M'  \"MMM \"YUM\" MPMMM  \"MMM \"YUMMMMP\" \"YUMMMMP\"\"MM,",
]

print(f"{company} {systemname} v{version}")

# do color gradients
start = (255, 0, 100)
end = (0, 200, 255)
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
# Manages the server's hash manifest database, a ledger of the files on the server with xxhash values to
# compare values with the client to indicate updated files.

from colorama import Fore, Style, init
from datetime import datetime
from platformdirs import PlatformDirs
from flask import Flask, request, jsonify, send_file
from functools import wraps
import secrets
import time
import csv
import hashlib
import sqlite3
import argparse
import tempfile
import os
import json
import concurrent.futures
import threading
import io
from pathlib import Path


cfgdirs = PlatformDirs(systemname, company)
config_path = cfgdirs.user_config_dir
config_location = f"{config_path}/cfg.json" # FIX: make real json file, accidentally used wrong var in a few places.
# to fix, config_path needs to be config_location.
credential_location = f"{config_path}/cred.csv"
default_world_db = f"{config_path}/worlds.db"
default_ledger_db = f"{config_path}/fileledger.db"

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

def write_config(configpath, host, port, serverroot, ledgerdblocation, worlddblocation, scaninterval, debugmode):
    data = {
        "host": host,
        "port": port,
        "serverroot": str(serverroot),
        "ledgerdblocation": str(ledgerdblocation),
        "worlddblocation": str(worlddblocation),
        "scaninterval": scaninterval,
        "debugmode": debugmode
    }
    configpath = Path(configpath)
    configpath.parent.mkdir(parents=True, exist_ok=True)
    if configpath is None:
        log.error("Config path is null when attempting to write config.")
        exit()
    with configpath.open("w") as f:
        json.dump(data, f, indent=4)
    log.info(f"Wrote config to {configpath}")

def read_config(configpath):
    configpath = Path(configpath)
    with configpath.open() as f:
        data = json.load(f)
    return [
        data["host"],
        data["port"],
        data["serverroot"],
        data["ledgerdblocation"],
        data["worlddblocation"],
        data["scaninterval"],
        data["debugmode"]
    ]


class storage_manager:
    class config_manager:
        def write_config(configpath, host, port, serverroot, ledgerdblocation, worlddblocation, scaninterval, debugmode):
            return write_config(configpath, host, port, serverroot, ledgerdblocation, worlddblocation, scaninterval, debugmode)

        def read_config(configpath):
            return read_config(configpath)



    # verify file hash is used to both generate and verify file hashes of the region files (and other)
    # it will be implemented this same way on the client to allow for file comparison.
    def verify_file_hash(path, chunk_size=4<<20):
        try:
            import xxhash
            log.debug("Hashing with xxhash")
            return xxhash.xxh64(open(path, 'rb').read()).hexdigest()
        except Exception:
            log.warn("Slow hashing is used, install python package \'xxhash\' to resolve this issue.")
            import zlib
            return format(zlib.crc32(open(path, "rb").read()) & 0xFFFFFFFF, "08x")

    # init_database is for all database init operations, there are two main databases including
    # the file ledger on the server that clients are able to request, as well as the world db
    # that the program uses to know what directories to be tracking. See the execute operations
    # for information about their schema.
    class init_database:
        # file tracker: the main database for tracking all file changes on the server side world,
        # this will be compressed in some way for transit to clients, constantly rechecked and
        # regenerated. It will probably be sent every 10 minutes, or more depending on load.
        def init_filetrack_ledger(path=default_ledger_db):
            log.info(f"Ledger db path is at {path}")
            log.info("Initing file tracking database...")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            conn = sqlite3.connect(path)
            conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                hash TEXT,
                size INTEGER,
                mtime INTEGER,
                version INTEGER DEFAULT 1,
                deleted INTEGER DEFAULT 0,
                last_synced INTEGER,
                world_id INTEGER
            )
            ''')
            conn.commit()
            conn.close()
            log.success(f"DB {path} init complete")

        def init_world_database(path=default_world_db):
            log.info(f"World db path is at {path}")
            log.info(f"Initing world tracking database...")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            conn = sqlite3.connect(path)
            conn.execute('''
            CREATE TABLE IF NOT EXISTS worlds (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                root_path TEXT NOT NULL,
                last_scan INTEGER
            )
            ''')
            conn.commit()
            conn.close()
            log.success(f"DB {path} init complete")

    class crud_operation:
        class create:
            # insert a new file into the tracking database
            # usage:
            # required
            # - path: path to the ledgerdb
            # - file_path: file path of the file you are adding
            # - file_hash: new hash of the file
            # - size: size in bytes of the file you are adding
            # - mtime: modified time of the file
            # - world_id: world id file belongs to. will work without, though that is very not advised
            # optional
            # - version: increment +1 each time file is updated (not handled here, just set to one)
            # - deleted: if file is deleted set this to 1, program wont handle this but it's useful data
            # - last_synced: last time file was synced to LOCAL CACHE!!!! that is delivered to subscribed servers
            def add_file_to_ledger(path, file_path, file_hash, size, mtime, version=1, deleted=0, last_synced=None, world_id=None):
                log.debug(f"Writing new file to ledger database at {path}")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                conn.execute('''
                    INSERT INTO files (path, hash, size, mtime, version, deleted, last_synced, world_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (file_path, file_hash, size, mtime, version, deleted, last_synced, world_id))
                conn.commit()
                conn.close()

            def add_tracked_world(path, name, root_path, last_scan=None):
                # add a world file into the world tracker db for the program to begin tracking it
                # usage:
                # - path: path of the world tracking database
                # - name: name of the world entry e.g. world, world_nether, world_the_end or even world_backup or similar
                # - root_path: the root path of the world file e.g. for amc /home/luna/anarchymc/world or something
                # - last_scan: dont change this, used for the program to know when rescans of the local files are needed.
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                conn.execute('INSERT INTO worlds (name, root_path, last_scan) VALUES (?, ?, ?)', (name, root_path, last_scan))
                conn.commit()
                conn.close()
                log.success(f"Added world {name} at {root_path} to the ledger.")

            def insert_row(db, path, hashval, size, mtime):
                conn = sqlite3.connect(db)
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO files (path, hash, size, mtime) VALUES (?, ?, ?, ?)",
                    (path, hashval, size, mtime)
                )
                conn.commit()
                conn.close()


        class read:
            # read files from ledger, is incremental to prevent huge data transfers at once.
            def read_ledger_paginated(path, offset=0, limit=100):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                rows = conn.execute('SELECT * FROM files LIMIT ? OFFSET ?', (limit, offset)).fetchall()
                conn.close()
                return rows

            # other function to read the entire ledger since im running low on time
            def read_ledger_full(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                rows = conn.execute('SELECT * FROM files').fetchall()
                conn.close()
                return rows

            # function to read files (e.g. server files) from the disk with sanitization
            def safe_read_file_from_disk(serverroot, file_path):
                serverroot = os.path.abspath(serveroot)
                target = os.path.abspath(os.path.join(serverroot, file_path))
                if not target.startswith(serveroot):
                    return None
                if not os.path.isfile(file_path):
                    return None
                with open(target, 'rb') as f:
                    return f.read()

            # read world entires from db, only path should be used
            def read_world_entries(path, offset=0, limit=100):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                rows = conn.execute('SELECT * FROM worlds LIMIT ? OFFSET ?', (limit, offset)).fetchall()
                conn.close()
                return rows

            def read_single_by_path(db, path):
                conn = sqlite3.connect(db)
                cur = conn.cursor()
                cur.execute("SELECT id, path, hash, size, mtime, version, deleted, last_synced, world_id FROM files WHERE path = ?", (path,))
                row = cur.fetchone()
                conn.close()
                return row


        class update:
            # function to modify file entires in the db:
            # usage:
            # - path: path of ledger db
            # - file_id: id of file you are modifying the properties for
            # - other args: arguments are processed wildcard, all arguments provided will be interpreted
            # and added to the database
            def modify_ledger_record(path, file_id, **kwargs):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                fields, values = [], []
                for key, val in kwargs.items():
                    fields.append(f"{key}=?")
                    values.append(val)
                values.append(file_id)
                conn.execute(f'UPDATE files SET {", ".join(fields)} WHERE id=?', values)
                conn.commit()
                conn.close()

            # update world entries (mostly used to update last_scsan and the world path)
            # usage:
            # required:
            # - path: path to the worlds database that you are updating
            # - world_id: the id of the world in the database that you are updating
            # optional (atleast one):
            # - name: new name value to update the name in the database
            # - root_path: new root path to update the path in the db
            # - last_scan: update the last_scan entry in the database
            def update_world_entry(path, world_id, name=None, root_path=None, last_scan=None):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                fields, values = [], []
                if name is not None:
                    fields.append("name=?")
                    values.append(name)
                if root_path is not None:
                    fields.append("root_path=?")
                    values.append(root_path)
                if last_scan is not None:
                    fields.append("last_scan=?")
                    values.append(last_scan)
                values.append(world_id)
                conn.execute(f'UPDATE worlds SET {", ".join(fields)} WHERE id=?', values)
                conn.commit()
                conn.close()
                log.success(f"World {world_id} has been updated.")

            def update_row(db, path, hashval, size, mtime):
                conn = sqlite3.connect(db)
                cur = conn.cursor()
                cur.execute(
                    "UPDATE files SET hash = ?, size = ?, mtime = ?, version = version + 1 WHERE path = ?",
                    (hashval, size, mtime, path)
                )
                conn.commit()
                conn.close()

        class delete:
            def remove_ledger_record(path, file_id):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                conn.execute('DELETE FROM files WHERE id=?', (file_id,))
                conn.commit()
                conn.close()

            def delete_world(path, world_id):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                conn.execute('DELETE FROM worlds WHERE id=?', (world_id,))
                conn.commit()
                conn.close()
                log.success(f"Deleted world {world_id}")

    class file_status_mng:
        # checks if db is empty, and fills db with hashes of files for first time init.
        def populate_db_with_file_hashes(root_path, threads, ledgerdblocation):
            def process_file(file_path):
                file_hash = storage_manager.verify_file_hash(file_path)
                size = os.path.getsize(file_path)
                mtime = int(os.path.getmtime(file_path))
                storage_manager.crud_operation.create.add_file_to_ledger(
                    ledgerdblocation, file_path, file_hash, size, mtime
                )
            try:
                # os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(ledgerdblocation)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM files")
                if cur.fetchone()[0] > 0:
                    conn.close()
                    log.warn("Denied. You may not populate db when db already has entries. Will assume you intended to update.")
                    storage_manager.file_status_mng.update_db_hashes(root_path, ledgerdblocation)
                conn.close()
            except sqlite3.OperationalError:
                log.warn("Failed to insert files into db, will reinit. You will need to syncall again.")
                storage_manager.init_database.init_filetrack_ledger()
                log.info("Performed init. Please run syncall again.")

            files = []
            for root, _, filenames in os.walk(root_path):
                for name in filenames:
                    files.append(os.path.join(root, name))
            log.info(f"Walked directories, discovered {len(files)} files")

            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                list(executor.map(process_file, files))

        # check for changed file sizes and modification date updates and calculate the new hash
        def update_db_hashes(root_path, ledgerdblocation, threads=12):
            def process_file(file_path):
                size = os.path.getsize(file_path)
                mtime = int(os.path.getmtime(file_path))
                conn = sqlite3.connect(ledgerdblocation)
                cur = conn.cursor()
                cur.execute("SELECT id, size, mtime FROM files WHERE path=?", (file_path,))
                row = cur.fetchone()
                if row:
                    fid, old_size, old_mtime = row
                    if size != old_size or mtime != old_mtime:
                        new_hash = storage_manager.verify_file_hash(file_path)
                        cur.execute(
                            "UPDATE files SET hash=?, size=?, mtime=?, version=version+1 WHERE id=?",
                            (new_hash, size, mtime, fid),
                        )
                        conn.commit()
                        log.debug(f"Updated {file_path}")
                else:
                    new_hash = storage_manager.verify_file_hash(file_path)
                    storage_manager.crud_operation.create.add_file_to_ledger(
                        ledgerdblocation, file_path, new_hash, size, mtime
                    )
                    log.debug(f"Added new file {file_path}")
                conn.close()

            log.info(f"Updating hashes in db for the server")
            files = []
            for root, _, filenames in os.walk(root_path):
                for name in filenames:
                    files.append(os.path.join(root, name))

            log.info(f"Discovered {len(files)} files to check")

            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                list(executor.map(process_file, files))

            log.success("Finished updating hashes in db.")

class client_interface:
    class authentication:
        def gen_token(credmancsv, username, hashedpassword):
            log.info(f"Generating token for {username}")
            rows = []
            token = secrets.token_hex(16)
            with open(credmancsv, newline='', mode='r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row[0] == username and row[1] == hashedpassword:
                        row[2] = token
                    rows.append(row)
            with open(credmancsv, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            return token

        def validate_token(credmancsv, inputtoken):
            with open(credmancsv, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) > 2 and row[2] == inputtoken:
                        return True
            return False

        def create_account(credmancsv, username, password):
            log.info(f"Creating account for {username}")
            hashedpassword = hashlib.sha256(password.encode()).hexdigest()
            with open(credmancsv, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([username, hashedpassword, ''])
            return True

        def remove_account(credmancsv, username):
            log.info(f"Deleting account for {username}")
            rows = []
            removed = False
            with open(credmancsv, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row[0] != username:
                        rows.append(row)
                    else:
                        removed = True
            with open(credmancsv, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            return removed

        def invalidate_token(credmancsv, inputtoken):
            log.info(f"Invalidated a token starting with {inputtoken[:8]}...")
            rows = []
            invalidated = True
            with open(credmancsv, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) > 2 and row[2] == inputtoken:
                        row[2] = ''
                        invalidated = True
                    rows.append(row)
            with open(credmancsv, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            return invalidated
    class system_interaction:
        def get_full_ledger():
            log.info("Reading full ledger from disk, as it was requested remotely.")
            return storage_manager.crud_operation.read.read_ledger_full(ledgerdblocation)

        def get_file(path):
            log.debug(f"Fetching file {path} for a remote server.")
            return storage_manager.crud_operation.read.safe_read_file_from_disk(serverroot, path)


# ---------- API ----------
app = Flask(__name__) # init app

# /
# root path for the server
@app.route("/", methods=["GET"])
def rootresponse():
    return jsonify({'version': version, "health": "healthy"})

# /auth/login
# POST endpoint, post credentials and return a new token to interact with the server
@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
    except:
        return jsonify({'error': 'must be in json format'})
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'missing credentials'})
    hashedpassword = hashlib.sha256(password.encode()).hexdigest()
    token = client_interface.authentication.gen_token(credential_location, username, hashedpassword)
    if not token:
        return jsonify({'error': 'invalid credentials'}), 401
    return jsonify({'token': token})

@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    try:
        data = request.get_json()
        token = data.get("token")
    except:
        return jsonify({'error': 'must be in json format'})
    if not token:
        return jsonify({'error': 'token is missing'}), 400
    if client_interface.authentication.validate_token(credential_location, token):
        success = client_interface.authentication.invalidate_token(credential_location, token)
        if not succes:
            return jsonify({'error': 'invalid token'}), 401
    else:
        return jsonify({'error': 'invalid token'}), 401
    return jsonify({'status': 'logged out'})

@app.route('/sync/manifest', methods=['GET'])
def sync_manifest():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'missing auth token'}), 400
    if not client_interface.authentication.validate_token(credential_location, token):
        return jsonify({'error': 'invalid token was provided'}), 401
    rows = storage_manager.crud_operation.read.read_ledger_full(ledgerdblocation)
    manifest = []
    for row in rows:
        manifest.append({
            'id': row[0],
            'path': row[1],
            'hash': row[2],
            'size': row[3],
            'mtime': row[4]
        })
    return jsonify({'manifest': manifest})

@app.route('/sync/file', methods=['GET'])
def sync_file():
    token = request.headers.get('Authorization')
    path = request.args.get('path')
    if not token or not path:
        return jsonify({"error": "token and path are required variables"}), 400
    if not client_interface.authentication.validate_token(credential_location, token):
        return jsonify({"error": "invalid authentication passed."})
    data = client_interface.system_interaction.get_file(path)
    if data is None:
        return jsonify({'error': 'file not found or access denied'}), 404
    return send_file(io.BytesIO(data), download_name=os.path.basename(path), as_attachment=True)

class interface:
    def confirmation_dialogue(question, default=True):
        if default == True:
            defanswer = "[Y/n]"
        else:
            defanswer = "[y/N]"
        userinput = input(f"{question} - {defanswer}")
        if (userinput.lower() == "y") or (userinput == "" and default == True):
            # log.debug(f"Answer to \'{question}\' was True.")
            return True
        else:
            # log.debug(f"Answer to \'{question}\' was False.")
            return False

    def init_config_request():
        configconfigpath = config_location
        confighost = input("Host (ip): ")
        configport = int(input("Port: "))
        configserverroot = input("Root server location: ")
        configscaninterval = int(input("Scan interval (s) (rec: 600): "))
        configdebugmode = input("Debug mode (true/false): ").lower() == "true"

        storage_manager.config_manager.write_config(
            configconfigpath,
            confighost,
            configport,
            configserverroot,
            default_ledger_db,
            default_world_db,
            configscaninterval,
            configdebugmode
        )

    def ifbackend(mode):
        modes = ["run", "init", "reset", "syncall", "info", "useredit"]
        log.debug(f"Interface backend running in mode {mode}")

        if mode not in modes:
            log.error(f"Mode \'{mode}\' is not supported, supported options are {modes}")

        match mode:
            case "useredit":
                log.info("Ok, what action would you like to perform?")
                dialogue_string = """
                Options:

                1 - add user

                2 - remove user

                Option
                """
                useredit_action = input(dialogue_string).strip()
                valid_options = ["1", "2"]
                if useredit_action not in valid_options:
                    log.error("Invalid option. Bye.")
                    exit()
                else:
                    os.makedirs(os.path.dirname(credential_location), exist_ok=True)
                    if not os.path.exists(credential_location):
                        with open(credential_location, "w", newline='') as f:
                            csv.writer(f).writerow(["username", "hashedpassword", "token"])
                if useredit_action == "1":
                    username = input("Username: ").strip()
                    if not username:
                        log.error("No username provided.")
                        exit()
                    password = input("Password: ")
                    if not password:
                        log.error("No password was provided")
                        exit()
                    with open(credential_location, newline='') as f:
                        reader = csv.reader(f)
                        for row in reader:
                            if row and row[0] == username:
                                log.error("User already exists.")
                                exit()
                    if client_interface.authentication.create_account(credential_location, username, password):
                        log.success(f"Created account {username}")
                    else:
                        log.error("Unknown error when creating account. Maybe clear configs, init, and try again. Nonfatal, however you probably want to stop the program.")

                elif useredit_action == "2":
                    accounts = []
                    log.debug(f"Loaded {len(accounts)} accounts for useredit operation")
                    with open(credential_location, newline='') as f:
                        reader = csv.reader(f)
                        for row in reader:
                            if not row:
                                continue
                            if row[0].lower() == "username" and row[1].lower() in ("hashedpassword","password"):
                                continue
                            accounts.append(row[0])
                    if not accounts:
                        log.warn("No accounts available to remove.")
                        exit()
                    for i, a in enumerate(accounts, start = 1):
                        log.info(f"{i} - {a}")
                    choice = input("Enter username or number to remove: ").strip()
                    target = None
                    if choice.isdigit():
                        idx = int(choice) - 1
                        if 0 <= idx < len(accounts):
                            target = accounts[idx]
                        else:
                            log.error("Invalid selection.")
                            exit()
                    else:
                        if choice in accounts:
                            target = choice
                        else:
                            log.error("Username not found.")
                            exit()
                    confirm = interface.confirmation_dialogue(f"Confirm delete user {target}?", default=False)
                    if not confirm:
                        log.error("User aborted.")
                        exit()
                    removed = client_interface.authentication.remove_account(credential_location, target)
                    if removed:
                        log.success(f"Removed account {target}")
                    else:
                        log.error("Unkown error removing account.")
                else:
                    log.error("Invalid option! Bye.")
                    exit()

            # run the api
            case "run":
                host, port, serverroot, ledgerdblocation, worlddblocation, scaninterval, debug = read_config(config_location)

                def background_scan():
                    while True:
                        log.info("Starting background file scan...")
                        for root, dirs, files in os.walk(serverroot):
                            for f in files:
                                p = os.path.join(root, f)
                                try:
                                    h = storage_manager.verify_file_hash(p)
                                except:
                                    log.debug(f"Failed to hash {p}")
                                    continue
                                s = os.path.getsize(p)
                                m = int(os.path.getmtime(p))
                                row = storage_manager.crud_operation.read.read_single_by_path(ledgerdblocation, p)
                                if row is None:
                                    storage_manager.crud_operation.create.insert_row(ledgerdblocation, p, h, s, m)
                                else:
                                    if row[2] != h or row[3] != s or row[4] != m:
                                        storage_manager.crud_operation.update.update_row(ledgerdblocation, p, h, s, m)
                                        log.debug(f"Updated file: {p}")
                        log.info(f"Scan complete. Next scan in {scaninterval} seconds.")
                        time.sleep(scaninterval)

                # Start the background scanning thread
                scan_thread = threading.Thread(target=background_scan, daemon=True)
                scan_thread.start()
                log.info("Background file scanning started")

                log.info(f"Starting API server on {host}:{port}")
                app.run(host=host, port=port, debug=False)
            # set up the app
            case "init":
                log.info("Credential info init")
                if not os.path.exists(credential_location):
                    log.info("Creds file doesn't exist, will make a new csv with no entries.")
                    with open(credential_location, "w", newline='') as f:
                        csv.writer(f).writerow(["username", "hashedpassword", "token"])
                else:
                    log.info("Creds file already exists")
                storage_manager.init_database.init_filetrack_ledger()
                storage_manager.init_database.init_world_database()
                log.info(f"System config path: {config_location}")
                if not os.path.exists(config_location):
                    log.warn(f"Config does NOT exist. You will be prompted to make one.")
                    makenewconfig = interface.confirmation_dialogue("No config file found, make one now?", default=True)
                    if makenewconfig:
                        log.info("Generating config, info must be filled out.")
                        interface.init_config_request()
                    else:
                        log.info("Skipping config generation.")
                else:
                    log.info("Found existing config.")
                    makenewconfig = interface.confirmation_dialogue("Found an existing config, make a new one?", default=False)
                    if makenewconfig:
                        log.info("Regenerating config, info must be filled out.")
                        interface.init_config_request()
                    else:
                        log.info("Skipping config regeneration.")
                if os.path.exists(config_location):
                    askpopulatedb = interface.confirmation_dialogue("Populate DB from root path in config?", default=True)
                    if askpopulatedb:
                        host, port, serverroot, ledgerdblocation, worlddblocation, scaninterval, debugmode = storage_manager.config_manager.read_config(config_location)
                        populationthreads = 12
                        log.info(f"Populating db with {populationthreads} threads for path {serverroot}")
                        storage_manager.file_status_mng.populate_db_with_file_hashes(serverroot, populationthreads, ledgerdblocation)
                        log.info("OK, populating db.")
                    else:
                        log.info("You probably want to populate the db at some point.")

            # reset configuration and tracking
            case "reset":
                pass

            case "syncall":
                askpopulatedb = interface.confirmation_dialogue("Populate DB from root path in config?", default=True)
                if askpopulatedb:
                    host, port, serverroot, ledgerdblocation, worlddblocation, scaninterval, debugmode = storage_manager.config_manager.read_config(config_location)
                    populationthreads = 12
                    log.info(f"Populating db with {populationthreads} threads for path {serverroot}")
                    storage_manager.file_status_mng.populate_db_with_file_hashes(serverroot, populationthreads, ledgerdblocation)
                    log.info("OK, populating db.")
                else:
                    log.info("You probably want to populate the db at some point.")
            case "info":
                pass

    def local_argument_parser():
        parser = argparse.ArgumentParser(description=systemname)

        parser.add_argument("runmode", help="Mode to run progam in, options: run, init, reset, syncall, info, useredit")

        inputargs = parser.parse_args()

        if inputargs.runmode:
            interface.ifbackend(inputargs.runmode)

if __name__ == "__main__":
    interface.local_argument_parser()