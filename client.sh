#!/bin/sh

echo "change directory ..."
cd "$(dirname $0)"

echo "active venv ..."
source venv/bin/activate

echo "start client ..."
python3 main.py client start client.cfg -v
