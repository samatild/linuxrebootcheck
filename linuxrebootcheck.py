"""
Script name: Linux Boot/Shutdown Quick-Analyzer
Version: 1.2
Git repo: https://github.com/samatild/linuxrebootcheck
"""
import os
import re
import gzip
import argparse
import subprocess


# Colors for the output
class Color:
    """ANSI color codes for terminal output formatting."""
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
parser.add_argument(
    "--serial-console-log",
    help="The name of the serial console log file to analyze"
)
parser.add_argument(
    "--version",
    action='version',
    version='Linux Boot/Shutdown Quick-Analyzer 1.2'
)

args = parser.parse_args()

filename = args.serial_console_log


def get_boot_info(filename=None):
    """
    Extract boot information from log files.

    Args:
        filename: Optional specific log file to analyze

    Returns:
        Tuple of boot count, boot timestamps and boot locations
    """
    boot_count = 0
    boot_timestamps = []
    boot_locations = []
    log_directory = '/var/log/'
    filenames = [filename] if filename else os.listdir(log_directory)

    for filename in filenames:
        filepath = os.path.join(log_directory, filename)
        if filename.startswith('dmesg') or filename == args.serial_console_log:
            try:
                if filename.endswith('.gz'):
                    file = gzip.open(filepath, 'rb')
                else:
                    file = open(filepath, 'rb')

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
                print(f"Error reading file {filepath}: {e}")

    return boot_count, boot_timestamps, boot_locations


def get_shutdown_info(filename=None):
    """
    Extract shutdown information from log files.

    Args:
        filename: Optional specific log file to analyze

    Returns:
        Tuple of shutdown count, timestamps, messages and locations
    """
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
    log_directory = '/var/log/'
    filenames = [filename] if filename else os.listdir(log_directory)

    for filename in filenames:
        filepath = os.path.join(log_directory, filename)
        if ('syslog' in filename or
                'messages' in filename or
                filename == args.serial_console_log):
            try:
                if filename.endswith('.gz'):
                    file = gzip.open(filepath, 'rt')
                else:
                    file = open(filepath, 'r')

                with file:
                    for line_number, line in enumerate(file, start=1):
                        for message in shutdown_messages:
                            if message in line:
                                shutdown_count += 1
                                shutdown_messages_matched.append(line.strip())
                                match_locations.append(
                                    (filename, line_number)
                                )
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
                print(f"Error reading file {filepath}: {e}")

    return (shutdown_count,
            shutdown_timestamps,
            shutdown_messages_matched,
            match_locations)


def is_journalctl_available():
    """Check if journalctl is available on the system."""
    try:
        result = os.system("which journalctl > /dev/null 2>&1")
        return result == 0
    except Exception:
        return False


def get_boot_info_from_journalctl():
    """
    Get boot information from journalctl.

    Returns:
        Tuple of boot count, boot timestamps and boot locations
    """
    boot_count = 0
    boot_timestamps = []
    boot_locations = []

    try:
        # Get list of boots from journalctl
        result = subprocess.run(
            ["journalctl", "--list-boots"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            boot_entries = result.stdout.strip().split('\n')
            boot_count = len(boot_entries)

            # Get more detailed information about each boot
            for boot_entry in boot_entries:
                boot_id = boot_entry.split()[0]
                boot_cmd = f"journalctl -b {boot_id} | grep 'Linux version'"
                boot_result = subprocess.run(
                    boot_cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )

                if boot_result.stdout:
                    # Extract timestamp from the journal entry
                    timestamp_cmd = (
                        f"journalctl -b {boot_id} -o short-iso | head -1"
                    )
                    timestamp_result = subprocess.run(
                        timestamp_cmd,
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    timestamp_line = timestamp_result.stdout.strip()
                    timestamp_match = re.search(
                        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
                        timestamp_line
                    )

                    if timestamp_match:
                        boot_timestamps.append(timestamp_match.group())

                    boot_locations.append(("journalctl", f"boot {boot_id}"))
    except Exception as e:
        print(f"Error getting boot info from journalctl: {e}")

    return boot_count, boot_timestamps, boot_locations


def get_shutdown_info_from_journalctl():
    """
    Get shutdown information from journalctl.

    Returns:
        Tuple of shutdown count, timestamps, messages and locations
    """
    shutdown_count = 0
    shutdown_timestamps = []
    shutdown_messages_matched = []
    match_locations = []

    try:
        # Get shutdown messages from journalctl
        shutdown_search = '|'.join([
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
            "Powering off"
        ])

        cmd = f"journalctl -o short-iso | grep -E '{shutdown_search}'"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True
        )

        if result.returncode == 0 and result.stdout:
            lines = result.stdout.strip().split('\n')
            shutdown_count = len(lines)

            for i, line in enumerate(lines, start=1):
                shutdown_messages_matched.append(line.strip())
                match_locations.append(("journalctl", i))

                timestamp_match = re.search(
                    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
                    line
                )
                if timestamp_match:
                    shutdown_timestamps.append(timestamp_match.group())
    except Exception as e:
        print(f"Error getting shutdown info from journalctl: {e}")

    return (shutdown_count,
            shutdown_timestamps,
            shutdown_messages_matched,
            match_locations)


# Try to get info from log files first
boot_count, boot_timestamps, boot_locations = get_boot_info(filename)
shutdown_count, shutdown_timestamps, shutdown_messages_matched, \
    match_locations = get_shutdown_info(filename)

# Check if local logs provided sufficient information
local_logs_provided_info = boot_count > 0 and shutdown_count > 0

# If we found limited info and journalctl is available, try that too
if not local_logs_provided_info and is_journalctl_available():
    print(Color.WARNING +
          "Limited information found in log files. Trying journalctl..." +
          Color.ENDC)

    if boot_count == 0:
        journal_boot_count, journal_boot_timestamps, \
            journal_boot_locations = get_boot_info_from_journalctl()
        boot_count += journal_boot_count
        boot_timestamps.extend(journal_boot_timestamps)
        boot_locations.extend(journal_boot_locations)

    if shutdown_count == 0:
        journal_results = get_shutdown_info_from_journalctl()
        journal_shutdown_count = journal_results[0]
        journal_shutdown_timestamps = journal_results[1]
        journal_shutdown_messages = journal_results[2]
        journal_match_locations = journal_results[3]

        shutdown_count += journal_shutdown_count
        shutdown_timestamps.extend(journal_shutdown_timestamps)
        shutdown_messages_matched.extend(journal_shutdown_messages)
        match_locations.extend(journal_match_locations)

print(Color.HEADER + "\nLinux Boot/Shutdown Quick-Analyzer\n" + Color.ENDC)


print(Color.OKBLUE + f'Number of boots: {boot_count}' + Color.ENDC)
for timestamp, location in zip(boot_timestamps, boot_locations):
    print(f'Boot at: {timestamp} UTC, ' +
          Color.OKBLUE +
          f'File: {location[0]}, Line: {location[1]}' +
          Color.ENDC)

print('\n\n')  # Separate boots and shutdowns with two empty paragraphs


print(Color.OKGREEN + f'Number of shutdowns: {shutdown_count}' + Color.ENDC)
for message, location in zip(shutdown_messages_matched, match_locations):
    print(f'Shutdown message: {message}, ' +
          Color.OKGREEN +
          f'File: {location[0]}, Line: {location[1]}' +
          Color.ENDC)

# End of script
