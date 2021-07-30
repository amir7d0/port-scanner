# port-scanner
A Python-based port scanner

## Features
- Scans all 65k ports
- Finds ports state : open, close, filtered, unfiltered, open | filtered
- Finds ports service by ``socket.getservbyport(port #)``
- Supports the following scan modes :
	- Connect Scan
	- Ack Scan
	- Syn Scan
	- Fin Scan
	- Window Scan

## Requirement
- Python 3.x
	- optparse
	- re
	- socket
	- struct
	- time
- Linux Operatin System


## Usage


```
Usage: app.py -t <IP or URL> -p <min-max> -s <scan mode> -d <delay>

Options:
  -h, --help            show this help message and exit
  -t TARGET, --target=TARGET
                        input target hostname
  -p PORT_RANGE, --port-range=PORT_RANGE
                        input range in format 'min-max'
  -s SCAN_MODE, --scan-mode=SCAN_MODE
                        CS => Connect Scan   AS => Ack Scan   SS => Syn Scan
                        FS => Fin Scan   WS => Window Scan
  -d DELAY, --delay=DELAY
                        delay for input packets

```
