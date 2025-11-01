# Manages the server's hash manifest database, a ledger of the files on the server with xxhash values to
# compare values with the client to indicate updated files.

from terminaloutput import Logger

log = Logger("StorageManager")
log.info("Hello from StorageManager")

class storage_manager:
    # verify file hash is used to both generate and verify file hashes of the region files (and other)
    # it will be implemented this same way on the client to allow for file comparison.
    def verify_file_hash(path, chunk_size=4<<20):
        try:
            import xxhash
            return xxhash.xxh64(open(path, 'rb').read()).hexdigest()
            log.succes("Hash check init succes")
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
        def init_filetrack_ledger(path="filetrack.db"):
            conn = sqlite3.connect(path)
            conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                hash TEXT,
                size INTEGER,
                mtime INTEGER,
                version INTEGER DEFAULT 1
                deleted INTEGER DEFAULT 0
                last_synced INTEGER,
                world_id INTEGER            
            )
            ''')
            conn.commit()
            conn.close()

        def init_world_database():
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
            def add_file_to_ledger():
                conn = sqlite3.connect(path, file_path, file_hash, size, mtime, version=1, deleted=0, last_synced=None, world_id=None)
                conn.execute('''
                    INSERT INTO files (path, hash, size, mtime, version, deleted, last_synced, world_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (file_path, file_hash, size, mtime, version, deleted, last_synced, world_id))
                conn.commit()
                conn.close

            def add_tracked_world(path, name, root_path, last_scan=None):
                # add a world file into the world tracker db for the program to begin tracking it
                # usage:
                # - path: path of the world tracking database
                # - name: name of the world entry e.g. world, world_nether, world_the_end or even world_backup or similar
                # - root_path: the root path of the world file e.g. for amc /home/luna/anarchymc/world or something
                # - last_scan: dont change this, used for the program to know when rescans of the local files are needed.
                conn = sqlite3.connect(path)
                conn.execute('INSERT INTO worlds (name, root_path, last_scan) VALUES (?, ?, ?)', (name, root_path, last_scan))
                conn.commit()
                conn.close()


        class read:
            # read files from ledger, is incremental to prevent huge data transfers at once.
            def read_ledger_paginated(path, offset=0 limit=100):
                conn = sqlite3.connect(path)
                rows = conn.execute('SELECT * FROM files LIMIT ? OFFSET ?', (limit, offset)).fetchall()
                conn.close()
                return rows
            # read world entires from db, only path should be used 
            def read_world_entries(path, offset=0, limit=100):
                conn = sqlite3.connect(path)
                rows = conn.execute('SELECT * FROM worlds LIMIT ? OFFSET ?', (limit, offset)).fetchall()
                conn.close()
                return rows
            
        class update:
            # function to modify file entires in the db:
            # usage:
            # - path: path of ledger db
            # - file_id: id of file you are modifying the properties for
            # - other args: arguments are processed wildcard, all arguments provided will be interpreted
            # and added to the database
            def modify_ledger_record(path, file_id, **kwargs):
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

        class delete:
            def remove_ledger_record():
                conn = sqlite3.connect(path)
                conn.execute('DELETE FROM files WHERE id=?', (file_id,))
                conn.commit()
                conn.close()

            def delete_world():
                conn = sqlite3.connect(path)
                conn.execute('DELETE FROM worlds WHERE id=?', (world_id,))
                conn.commit()
                conn.close()