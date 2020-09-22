class CorecproError(Exception):
    """Base class for exceptions in CORECPRO

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class SambaError(CorecproError):
    """Exception raised for errors in Samba that cannot be covered by default Python errors

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class NotNmapError(SambaError):
    """Exception raised if there is confirmation that an SMB packet is NOT an Nmap SMB packet

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message
