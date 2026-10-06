#!/usr/bin/env python3
"""Send commands to the Flipper CLI over serial and print the replies.

ufbt's own `cli` subcommand wants a tty, which makes it awkward to drive from a
script. This talks to the same CLI directly.
"""
import os
import sys
import time

import serial
from serial.tools.list_ports import comports

# Seconds to collect output for after each command.
WINDOW = os.environ.get("FLIPCLI_WINDOW", "2")


def find_port():
    for port in comports():
        if "flip" in (port.device or "").lower():
            return port.device
    raise SystemExit("no Flipper serial port found")


def main():
    commands = sys.argv[1:] or ["help"]
    port = find_port()

    with serial.Serial(port, timeout=1) as ser:
        ser.baudrate = 230400
        ser.flushOutput()
        ser.flushInput()
        # Wake the CLI and swallow the banner.
        ser.write(b"\r")
        time.sleep(0.4)
        ser.read_until(b">: ")

        for command in commands:
            # Drain anything left over from the previous command first, otherwise
            # a stale prompt satisfies the read immediately.
            while ser.in_waiting:
                ser.read(ser.in_waiting)

            ser.write(command.encode() + b"\r")

            # Read on a wall-clock window rather than until a prompt: some
            # commands (log) never return one.
            deadline = time.time() + float(WINDOW)
            chunks = []
            while time.time() < deadline:
                if ser.in_waiting:
                    chunks.append(ser.read(ser.in_waiting))
                else:
                    time.sleep(0.05)

            text = b"".join(chunks).decode("utf-8", errors="replace")
            print(f"--- {command} ---")
            print(text.replace("\r", ""))


if __name__ == "__main__":
    main()
