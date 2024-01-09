# Linux Boot/Shutdown Quick-Analyzer

The Linux Boot/Shutdown Quick-Analyzer is a Python script that analyzes Linux boot and shutdown logs.

![Preview](assets/screenshot.png)

## Description

This script parses system logs to find boot and shutdown events. It works with both gzip-compressed and uncompressed logs.

The script provides the following information:

- The number of boot events, along with the timestamp, filename, and line number for each event.
- The number of shutdown events, along with the associated message, filename, and line number for each event.

The script can analyze all suitable log files in the current directory, or a specific file if provided.

## Requirements

You need to have Python 3 installed on your machine.

## Usage

To use the script, navigate to the directory containing your logs (usually /var/log) and run the following command:

```bash
curl https://raw.githubusercontent.com/samatild/linuxrebootcheck/main/linuxrebootcheck.py | python3
```

To analyze Serial Console file, you need to download the script and use the --serial-console-log argument followed by the filename:
```bash
curl -O https://raw.githubusercontent.com/samatild/linuxrebootcheck/main/linuxrebootcheck.py
python3 linuxrebootcheck.py --serial-console-log <your_log_file>
```


## Command Line Arguments

The script supports the following command line arguments:

- `--serial-console-log`: This argument allows you to specify a particular log file to analyze. This is particularly useful when working with Azure specific serial console log files. When this argument is used, the script will only analyze the provided file, instead of all suitable log files in the current directory.

- `--version`: Prints current version.
  
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](LICENSE)

