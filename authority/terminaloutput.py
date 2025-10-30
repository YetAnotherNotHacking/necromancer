try:
    from colorama import Fore, Style, init
    from datetime import datetime
except Exception as e:
    print(f"Dependancies are not met. Install them.\nSpecfic error:\n{e}")

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
        self._log('ERORR', msg)
    def succes(self, msg):
        self._log('SUCCESS', msg)
    def debug(self, msg):
        self._log('DEBUG', msg)