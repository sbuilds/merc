#!/usr/bin/env python3

from pathlib import Path
import argparse

import database as db

parser = argparse.ArgumentParser()
parser.add_argument('path', metavar='PATH', action='store', help="")
args = parser.parse_args()

path = Path(args.path)
files = list(path.glob('*'))
db.store_files(files)

