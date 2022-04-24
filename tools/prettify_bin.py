#!/usr/bin/env python3
import sys

def reformat_bin(filename):
    data = open(filename, 'rb').read()
    lines = [data[i:(i+16)].hex() for i in range(0, len(data), 16)]
    formatted_lines = [f"{x} {y}" for x, y in zip(lines[::2], lines[1::2])]
    if len(lines) & 1 == 1:
        formatted_lines.append(lines[-1])
    with open(f"{filename}.pretty", 'w') as fp:
        print('\n'.join(formatted_lines), file=fp)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('requires target bin file(s) to beautify', file=sys.stderr)
        sys.exit(1)
    files = sys.argv[1:]
    for file in files:
        try:
            reformat_bin(file)
        except Exception as e:
            print(f'failed to beautify {file}', file=sys.stderr)
            print(f'exception: {e}')
