# Manages the server's hash manifest database, a ledger of the files on the server with xxhash values to
# compare values with the client to indicate updated files.

from terminaloutput import Logger

log = Logger("StorageManager")
log.info("Hello from StorageManager")

class storage_manager:
    def verify_file_hash(path, chunk_size=4<<20):
        try:
            import xxhash
            return xxhash.xxh64(open(path, 'rb').read()).hexdigest()
            log.succes("Hash check init succes")
        except Exception:
            log.warn("Slow hashing is used, install python package \'xxhash\' to resolve this issue.")
            import zlib
            return format(zlib.crc32(open(path, "rb").read()) & 0xFFFFFFFF, "08x")

hash = storage_manager.verify_file_hash("/home/dread/necromancer/test.txt")
print(hash)