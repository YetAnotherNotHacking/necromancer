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