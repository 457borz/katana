# Katana
Simple asynchronous ssh bruteforcing tool, written in Python.
Compatible with [masscan](https://github.com/robertdavidgraham/masscan) output.
Can detect [Kippo](https://github.com/desaster/kippo) honeypot.

## Disclaimer
This script is created for education purposes only!
Author will not be held responsible in the event any criminal charges be brought against any individuals misusing this tool to break the law!

## Requirements
Python 3.6+,
 [asyncssh](https://github.com/ronf/asyncssh)

## Usage
`python katana.py hosts.txt -c 250 -t 5`
You can see full list of parameters with:
`python katana.py --help`

Put credentials list in `credentials.txt` file (`root:root` for example).
Results will be added to the file in same directory with script.
