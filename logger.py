# -*- coding: utf-8 -*-
#
# Copyright © 2020 The Aerospace Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
# OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
# OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Used to generate and write CORECPRO logs that are Splunk-readable.
This custom logger module was necessary as the default Python module for logging does not provide the features
necessary to create logs that are specific to CORECPRO's needs. It contains a class designed to store data—LogData—and a
separate class—Logger—to write that data.
"""
from datetime import datetime
from time import time
from os import path
from out import Out


class LogData:
    """Holds logging information for CORECPRO logs for non-reverse shell events.
    Log data should be passed to Logger for writing to the filesystem.
    """

    def __init__(self, action: str, severity: str, confidence: str, software: str, error: str = None,
                 packet: bytes = None):
        action_opt: list = ["interaction",
                            "probe",
                            "version scan",
                            "vulnerability scan",
                            "exploitation"]
        severity_opt: list = ["info",
                              "low",
                              "medium",
                              "high"]
        confidence_opt: list = ["potential",
                                "confirmed",
                                "N/A"]
        software_opt: list = ["nmap",
                              "metasploit",
                              "unknown"]

        if action not in action_opt:
            raise ValueError("CORECPRO-Logger Error: Action '" + action + "' is not a valid action. Valid actions: "
                             + str(action_opt))
        if severity not in severity_opt:
            raise ValueError("CORECPRO-Logger Error: Severity '" + severity + "' is not a valid severity level. Valid "
                                                                              "severities: " + str(severity_opt))
        if confidence not in confidence_opt:
            raise ValueError("CORECPRO-Logger Error: Confidence '" + confidence +
                             "' is not a valid confidence level. Valid confidence levels: " + str(confidence_opt))

        if software not in software_opt:
            raise ValueError("CORECPRO-Logger Error: Software '" + software + "' is not valid software. Valid "
                                                                              "software: " + str(software_opt))

        self.action = action
        self.severity = severity
        self.confidence = confidence
        self.software = software
        self.error = error
        self.packet = packet

    def out(self, verbose: bool) -> str:
        """Prints log in a Splunk-readable format.

        :param verbose: If verbosity is turned on and the software runs into an error, the packet is dumped
        :return: str of the log in a Splunk-readable format
        """
        if self.error is None:  # No error, no printing of error or packet
            return "\" confidence=\"" + self.confidence + "\" severity=\"" + self.severity + "\" software=\"" \
                   + self.software + "\" action=\"" + self.action + "\""
        elif verbose:  # Print error, print packet
            return "\" confidence=\"" + self.confidence + "\" severity=\"" + self.severity + "\" software=\"" \
                   + self.software + "\" action=\"" + self.action + "\" error=\"" + self.error + "\" packet=\"" \
                   + str(self.packet) + "\""
        else:  # Print error, don't print packet
            return "\" confidence=\"" + self.confidence + "\" severity=\"" + self.severity + "\" software=\"" \
                   + self.software + "\" action=\"" + self.action + "\" error=\"" + self.error + "\""


class Logger:
    """Logging class for CORECPRO logs, which writes logs based on the LogData object or based on shell commands."""

    def __init__(self, location_main: str = path.dirname(path.realpath(__file__)),
                 location_shell: str = path.dirname(path.realpath(__file__))):
        self.location_main: str = location_main
        self.location_shell: str = location_shell
        self.filename: str = "CORECPRO-LOG-"
        self.verbose: bool = False
        self.last_event = dict()  # Last log written
        self.stdout: bool = False
        self.cool_down: int = 30  # Cool down between identical logs in seconds

    def write_empty_main(self):
        """Writes an empty file for the main directory; used for testing."""
        file = open(self.location_main + "/" + self.filename + datetime.now().astimezone().strftime("%Y-%b-%d"), 'a')
        file.close()

    def write_empty_shell(self):
        """Writes an empty file for the shell directory; used for testing."""
        file = open(self.location_shell + "/" + self.filename + "SHELL-" + datetime.now().astimezone().
                    strftime("%Y-%b-%d"), 'a')
        file.close()

    def __clean_events(self):
        """Cleans the event data in self.last_event to prevent it from getting overfilled.
        Ran by the self.write method upon each log write."""
        to_be_removed = list()
        for event in self.last_event:
            if self.last_event[event] + self.cool_down < time():
                to_be_removed.append(event)

        for event in to_be_removed:
            del self.last_event[event]

    def write(self, data: LogData, who: str, port: int):
        """Writes Splunk-readable CORECPRO logs using custom LogData object

        :param data: LogData object
        :param who: IP address of the attacker
        :param port: Port which the attacker is interacting with
        """

        log = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S.%f%z") + " src=\"" + who \
              + "\" dest=\"" + str(port) + data.out(self.verbose)

        log_nd = ' '.join(log.split()[1:])  # "Log no date" required when we decide whether to print the same log
        # again or not. Limited by the self.cool_down variable.

        if log_nd not in self.last_event or \
                (self.last_event[log_nd] + self.cool_down < time()):
            if self.stdout:
                Out.norm(log)
            file = open(self.location_main + "/" + self.filename + datetime.now().astimezone().strftime("%Y-%b-%d"), 'a')
            file.write(log + "\n")
            file.close()
            self.last_event[log_nd] = time()
            self.__clean_events()

    def write_shell(self, cmd: bytes, who: str, attacker: bool):
        if attacker:
            data_type: str = "attacker_cmd"
        else:
            data_type: str = "data_returned"
        log = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S.%f%z") + " src=\"" + who \
              + "\" " + data_type + "{\n" + cmd.decode("UTF-8") + "}"

        if self.stdout:
            Out.norm(log)
        shell_file = open(self.location_shell + "/" + self.filename + "SHELL-" + datetime.now().astimezone().
                          strftime("%Y-%b-%d"), 'a')
        shell_file.write(log + "\n")
        shell_file.close()
