"""
Script name: Linux Boot/Shutdown Quick-Analyzer
Version: 1.2
Git repo: https://github.com/samatild/linuxrebootcheck
"""
import re
import gzip
import argparse
import subprocess
from pathlib import Path
import time


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
    "--log-dir",
    default="/var/log/",
    help="Directory containing log files (default: /var/log/)"
)
parser.add_argument(
    "--version",
    action='version',
    version='Linux Boot/Shutdown Quick-Analyzer 1.2'
)

args = parser.parse_args()

filename = args.serial_console_log
log_directory = args.log_dir


def get_log_files(log_dir, patterns):
    """
    Get log files matching specified patterns.
    
    Args:
        log_dir: Directory to search for log files
        patterns: List of glob patterns to match
        
    Returns:
        List of matching file paths
    """
    matching_files = []
    log_path = Path(log_dir)
    
    if not log_path.exists():
        print(f"{Color.WARNING}Warning: Log directory {log_dir} "
              f"does not exist{Color.ENDC}")
        return matching_files
    
    if not log_path.is_dir():
        print(f"{Color.WARNING}Warning: {log_dir} is not a directory"
              f"{Color.ENDC}")
        return matching_files
    
    for pattern in patterns:
        try:
            matching_files.extend(log_path.glob(pattern))
        except Exception as e:
            print(f"{Color.WARNING}Warning: Error matching pattern "
                  f"{pattern}: {e}{Color.ENDC}")
    
    # Remove duplicates and filter out non-files
    matching_files = list(set([f for f in matching_files if f.is_file()]))
    return matching_files


def extract_timestamp_from_line(line, file_mtime=None):
    """
    Extract timestamp from a log line with fallback to file modification time.
    
    Args:
        line: The log line to extract timestamp from
        file_mtime: File modification time as fallback
        
    Returns:
        Extracted timestamp string or None
    """
    # Try to extract ISO timestamp first
    timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line)
    if timestamp_match:
        return timestamp_match.group()
    
    # Try syslog timestamp format (e.g., "Dec 15 10:30:45")
    syslog_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if syslog_match:
        return syslog_match.group()
    
    # Try RFC 3164 format (e.g., "Dec 15 10:30:45 hostname")
    rfc3164_match = re.search(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+', line
    )
    if rfc3164_match:
        return rfc3164_match.group(1)
    
    # Fallback to file modification time if available
    if file_mtime:
        return time.strftime('%Y-%m-%dT%H:%M:%S', 
                           time.localtime(file_mtime))
    
    return None


def process_log_file(filepath, search_patterns, max_lines=None):
    """
    Process a log file efficiently, optionally limiting lines for performance.
    
    Args:
        filepath: Path to the log file
        search_patterns: List of patterns to search for
        max_lines: Maximum number of lines to process (None for all)
        
    Yields:
        Tuples of (line_number, line, timestamp)
    """
    try:
        file_path = Path(filepath)
        file_mtime = file_path.stat().st_mtime if file_path.exists() else None
        
        # Determine file type and open appropriately
        if str(filepath).endswith('.gz'):
            with gzip.open(filepath, 'rt', encoding='utf-8', 
                          errors='ignore') as file:
                for line_number, line in enumerate(file, start=1):
                    if max_lines and line_number > max_lines:
                        break
                    timestamp = extract_timestamp_from_line(line, file_mtime)
                    yield line_number, line, timestamp
        else:
            with open(filepath, 'r', encoding='utf-8', 
                     errors='ignore') as file:
                for line_number, line in enumerate(file, start=1):
                    if max_lines and line_number > max_lines:
                        break
                    timestamp = extract_timestamp_from_line(line, file_mtime)
                    yield line_number, line, timestamp
                    
    except Exception as e:
        print(f"{Color.FAIL}Error reading file {filepath}: {e}{Color.ENDC}")


def normalize_timestamp(timestamp_str):
    """
    Normalize timestamp to ISO format for consistent comparison.
    
    Args:
        timestamp_str: Timestamp string in various formats
        
    Returns:
        Normalized ISO timestamp string or None
    """
    if not timestamp_str:
        return None
    
    # Already in ISO format
    iso_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', timestamp_str)
    if iso_match:
        return iso_match.group(1)
    
    # Syslog format (e.g., "Jul 21 13:38:59")
    syslog_match = re.search(r'(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', timestamp_str)
    if syslog_match:
        month, day, time_str = syslog_match.groups()
        # Convert month name to number
        months = {
            'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
            'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
            'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
        }
        month_num = months.get(month, '01')
        # Assume current year if not specified
        current_year = time.strftime('%Y')
        return f"{current_year}-{month_num}-{day.zfill(2)}T{time_str}"
    
    return None


def are_timestamps_close(ts1, ts2, max_diff_seconds=300):
    """
    Check if two timestamps are within a specified time window.
    
    Args:
        ts1: First timestamp string
        ts2: Second timestamp string
        max_diff_seconds: Maximum difference in seconds (default: 5 minutes)
        
    Returns:
        True if timestamps are close, False otherwise
    """
    if not ts1 or not ts2:
        return False
    
    try:
        # Parse timestamps
        t1 = time.strptime(ts1, '%Y-%m-%dT%H:%M:%S')
        t2 = time.strptime(ts2, '%Y-%m-%dT%H:%M:%S')
        
        # Convert to seconds since epoch
        t1_sec = time.mktime(t1)
        t2_sec = time.mktime(t2)
        
        return abs(t1_sec - t2_sec) <= max_diff_seconds
    except ValueError:
        return False


def deduplicate_events(events, max_diff_seconds=300):
    """
    Remove duplicate events based on timestamp proximity.
    
    Args:
        events: List of (timestamp, location, message) tuples
        max_diff_seconds: Maximum time difference to consider duplicates
        
    Returns:
        Deduplicated list of events
    """
    if not events:
        return []
    
    # Sort by timestamp for easier deduplication
    sorted_events = sorted(events, key=lambda x: x[0] if x[0] else '')
    deduplicated = []
    
    for event in sorted_events:
        timestamp, location, message = event
        
        # Check if this event is a duplicate of any existing event
        is_duplicate = False
        for existing_event in deduplicated:
            existing_timestamp, existing_location, existing_message = existing_event
            
            if are_timestamps_close(timestamp, existing_timestamp, max_diff_seconds):
                is_duplicate = True
                break
        
        if not is_duplicate:
            deduplicated.append(event)
    
    return deduplicated


def get_boot_info(filename=None):
    """
    Extract boot information from log files.

    Args:
        filename: Optional specific log file to analyze

    Returns:
        Tuple of boot count, boot timestamps and boot locations
    """
    boot_events = []
    
    # Define patterns for boot-related log files
    boot_patterns = ['dmesg*', 'kern.log*', 'syslog*']
    
    if filename:
        files_to_check = [Path(log_directory) / filename]
    else:
        files_to_check = get_log_files(log_directory, boot_patterns)
    
    # Add serial console log if specified
    if args.serial_console_log:
        serial_log = Path(log_directory) / args.serial_console_log
        if serial_log.exists() and serial_log not in files_to_check:
            files_to_check.append(serial_log)

    for filepath in files_to_check:
        for line_number, line, timestamp in process_log_file(filepath, ["Linux version"]):
            if "Linux version" in line:
                normalized_timestamp = normalize_timestamp(timestamp)
                if normalized_timestamp:
                    boot_events.append((
                        normalized_timestamp,
                        (filepath.name, line_number),
                        line.strip()
                    ))
                    
            # Also check for rtc_cmos pattern for additional boot detection
            if "rtc_cmos" in line and timestamp:
                normalized_timestamp = normalize_timestamp(timestamp)
                if normalized_timestamp:
                    boot_events.append((
                        normalized_timestamp,
                        (filepath.name, line_number),
                        line.strip()
                    ))

    # Deduplicate boot events
    deduplicated_boots = deduplicate_events(boot_events, max_diff_seconds=300)
    
    # Extract results
    boot_count = len(deduplicated_boots)
    boot_timestamps = [event[0] for event in deduplicated_boots]
    boot_locations = [event[1] for event in deduplicated_boots]

    return boot_count, boot_timestamps, boot_locations


def get_shutdown_info(filename=None):
    """
    Extract shutdown information from log files.

    Args:
        filename: Optional specific log file to analyze

    Returns:
        Tuple of shutdown count, timestamps, messages and locations
    """
    shutdown_events = []
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
    
    # Define patterns for shutdown-related log files
    shutdown_patterns = ['syslog*', 'messages*', 'auth.log*', 'daemon.log*']
    
    if filename:
        files_to_check = [Path(log_directory) / filename]
    else:
        files_to_check = get_log_files(log_directory, shutdown_patterns)
    
    # Add serial console log if specified
    if args.serial_console_log:
        serial_log = Path(log_directory) / args.serial_console_log
        if serial_log.exists() and serial_log not in files_to_check:
            files_to_check.append(serial_log)

    for filepath in files_to_check:
        for line_number, line, timestamp in process_log_file(filepath, shutdown_messages):
            for message in shutdown_messages:
                if message in line:
                    normalized_timestamp = normalize_timestamp(timestamp)
                    if normalized_timestamp:
                        shutdown_events.append((
                            normalized_timestamp,
                            (filepath.name, line_number),
                            line.strip()
                        ))
                    break

    # Deduplicate shutdown events
    deduplicated_shutdowns = deduplicate_events(shutdown_events, max_diff_seconds=300)
    
    # Extract results
    shutdown_count = len(deduplicated_shutdowns)
    shutdown_timestamps = [event[0] for event in deduplicated_shutdowns]
    shutdown_messages_matched = [event[2] for event in deduplicated_shutdowns]
    match_locations = [event[1] for event in deduplicated_shutdowns]

    return (shutdown_count,
            shutdown_timestamps,
            shutdown_messages_matched,
            match_locations)


def is_journalctl_available():
    """Check if journalctl is available on the system."""
    try:
        result = subprocess.run(["which", "journalctl"], 
                              capture_output=True, 
                              text=True, 
                              check=False)
        return result.returncode == 0
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

print(Color.OKBLUE + f'Number of boots (deduplicated): {boot_count}' + Color.ENDC)
if boot_count > 0:
    print(Color.OKBLUE + "Boot events:" + Color.ENDC)
    for timestamp, location in zip(boot_timestamps, boot_locations):
        print(f'  {timestamp} UTC - File: {location[0]}, Line: {location[1]}')
else:
    print("  No boot events found")

print('\n')  # Separate boots and shutdowns

print(Color.OKGREEN + f'Number of shutdowns (deduplicated): {shutdown_count}' + Color.ENDC)
if shutdown_count > 0:
    print(Color.OKGREEN + "Shutdown events:" + Color.ENDC)
    for timestamp, location in zip(shutdown_timestamps, match_locations):
        print(f'  {timestamp} UTC - File: {location[0]}, Line: {location[1]}')
else:
    print("  No shutdown events found")

# End of script
