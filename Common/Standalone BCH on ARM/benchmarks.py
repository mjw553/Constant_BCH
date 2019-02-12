#!/usr/bin/env python3
import serial
import sys
import os
import subprocess
import hashlib

dev = serial.Serial("/dev/ttyUSB0", 115200)

try:
    binaries = [x for x in os.listdir('bin') if 'speed.bin' in x]
except FileNotFoundError:
    print("There is no bin/ folder. Please first make binaries.")
    sys.exit(1)

print("This script flashes the benchmarking binaries onto the board, ")
print(" and then writes the resulting output to the benchmarks directory.")

for binary in binaries:
    binpath = os.path.join("bin", binary)

    info = binary.split('_')
    primitive = '_'.join(info[:2])
    scheme = '_'.join(info[2:-2])
    implementation = info[-2]

    if len(sys.argv) > 1 and scheme not in sys.argv[1:]:
        continue

    print("Flashing {}..".format(binpath))

    subprocess.run(["st-flash", "write", binpath, "0x8000000"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("Flashed, now running benchmarks..".format(binary))

    state = 'waiting'
    marker = b''

    # This parses test vector output starting with a number of leading '=',
    #  and expects a hashtag '#' after the test vector output.
    while True:
        x = dev.read()
        if state == 'waiting':
            if x == b'=':
                marker += x
                continue
            # If we saw at least 5 equal signs, assume we've probably started
            elif marker.count(b'=') > 5:
                state = 'beginning'
                vector = []
                print("  .. found output marker..")
        if state == 'beginning':
            if x == b'=':
                continue
            else:
                state = 'reading'
        elif state == 'reading':
            if x == b'#':
                break
            else:
                vector.append(x)

    filename = os.path.join('benchmarks/', primitive, scheme, implementation)
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    #with open(filename, 'w') as f:
    with open(filename, 'w') as f:
        f.write(b''.join(vector).decode('utf-8').strip())
    print("  .. wrote benchmarks!")
