"""
Script name: Linux Boot/Shutdown Quick-Analyzer
Version: 1.0
Git repo: https://github.com/samatild/linuxrebootcheck
"""
import os
import re
import gzip
import argparse


# Colors for the output
class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Parser for command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--serial-console-log",
                    help="The name of the serial console log file to analyze")
parser.add_argument("--version",
                    action='version',
                    version='Linux Boot/Shutdown Quick-Analyzer 1.0')

args = parser.parse_args()

filename = args.serial_console_log


def get_boot_info(filename=None):
    boot_count = 0
    boot_timestamps = []
    boot_locations = []
    filenames = [filename] if filename else os.listdir('.')

    for filename in filenames:
        if filename.startswith('dmesg') or filename == args.serial_console_log:
            try:
                if filename.endswith('.gz'):
                    file = gzip.open(filename, 'rb')
                else:
                    file = open(filename, 'rb')

                with file:
                    for line_number, line in enumerate(file, start=1):
                        line = line.decode('utf-8', errors='ignore')
                        if "Linux version" in line:
                            boot_count += 1
                            boot_locations.append((filename, line_number))
                        if "rtc_cmos" in line:
                            timestamp = re.search(
                                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line
                                )
                            if timestamp:
                                boot_timestamps.append(timestamp.group())
            except Exception as e:
                print(f"Error reading file {filename}: {e}")

    return boot_count, boot_timestamps, boot_locations


def get_shutdown_info(filename=None):
    shutdown_count = 0
    shutdown_timestamps = []
    shutdown_messages_matched = []
    match_locations = []
    shutdown_messages = [
        "System is going down",
        "systemd-shutdown",
        "reboot: Power down",
        "reboot: System halted",
        "Stopping remaining cryptographic devices",
        "Deactivating swap",
        "Unmounting file systems",
        "Reached target Shutdown",
        "Reached target Final Step",
        "Power down",
        "Powering off",
    ]
    filenames = [filename] if filename else os.listdir('.')
    for filename in filenames:
        if ('syslog' in filename or
            'messages' in filename or
                filename == args.serial_console_log):
            try:
                if filename.endswith('.gz'):
                    file = gzip.open(filename, 'rt')
                else:
                    file = open(filename, 'r')

                with file:
                    for line_number, line in enumerate(file, start=1):
                        for message in shutdown_messages:
                            if message in line:
                                shutdown_count += 1
                                shutdown_messages_matched.append(line.strip())
                                match_locations.append((filename, line_number))
                                timestamp = re.search(
                                    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
                                    line
                                    )
                                if timestamp:
                                    shutdown_timestamps.append(
                                        timestamp.group()
                                        )
                                break
            except Exception as e:
                print(f"Error reading file {filename}: {e}")

    return (shutdown_count,
            shutdown_timestamps,
            shutdown_messages_matched,
            match_locations
            )


boot_count, boot_timestamps, boot_locations = get_boot_info(filename)

(shutdown_count,
    shutdown_timestamps,
    shutdown_messages_matched,
    match_locations) = get_shutdown_info(filename)

print(Color.HEADER + "\nLinux Boot/Shutdown Quick-Analyzer\n" + Color.ENDC)


print(Color.OKBLUE + f'Number of boots: {boot_count}' + Color.ENDC)
for timestamp, location in zip(boot_timestamps, boot_locations):
    print(f'Boot at: {timestamp} UTC, ' + Color.OKBLUE + f'File: {location[0]}, Line: {location[1]}' + Color.ENDC)

print('\n\n')  # Separate boots and shutdowns with two empty paragraphs


print(Color.OKGREEN + f'Number of shutdowns: {shutdown_count}' + Color.ENDC)
for message, location in zip(shutdown_messages_matched, match_locations):
    print(f'Shutdown message: {message}, ' + Color.OKGREEN + f'File: {location[0]}, Line: {location[1]}' + Color.ENDC)

# End of script
