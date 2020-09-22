from sys import stderr

red: str = '\033[31m'
orange: str = '\033[33m'
blue: str = '\033[34m'
green = '\033[32m'
end: str = '\033[0m'


class Out:
    """Prints messages to console using Msfconsole-inspired colors and format"""
    @staticmethod
    def err(message: str):
        """Prints error message to sys.stderr using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{red}[-] " + message + f"{end}", file=stderr)

    @staticmethod
    def warn(message: str):
        """Prints warning message using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{orange}[!] " + message + f"{end}")

    @staticmethod
    def norm(message: str):
        """Prints a message using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{blue}[*] " + message + f"{end}")

    @staticmethod
    def good(message: str):
        """Prints a message using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{green}[+] " + message + f"{end}")
