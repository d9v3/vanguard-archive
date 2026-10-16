#!/bin/bash
# Double-clic dans le Finder : lance netscan (et le compile la première fois sur ce Mac).
cd "$(dirname "$0")"
if [ ! -x ./netscan ] || [ ../source/Cargo.toml -nt ./netscan ]; then
  ./compiler.command || exit 1
fi
exec ./netscan
