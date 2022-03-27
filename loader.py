#!/usr/bin/env python3

import argparse
import json
import redis
import logging
import os
from pathlib import Path

import src.database as db

parser = argparse.ArgumentParser()
parser.add_argument('--path', metavar='PATH', action='store', 
    help="Path to load file from into database")
parser.add_argument('--redis', action='store_true', 
    help="Also load into redis for processing")
parser.add_argument('--redis-only', action='store_true', 
    help="Only read existing files from database into redis for processing")
args = parser.parse_args()

logging.getLogger().setLevel(os.environ.get('LOGGING_LEVEL','INFO'))
logger = logging.getLogger(__name__)

if not args.redis_only:

    path = Path(args.path)
    files = list(path.glob('*'))
    db.store_files(files)

if args.redis or args.redis_only:
    files = db.read_files()
    client = redis.StrictRedis(host='127.0.0.1', port=6379, db=0)
    try:
        client.xgroup_create('process','process-group', mkstream=True)
    except redis.exceptions.ResponseError as e:
        pass

    for file in files:
        rec_id = client.xadd('process', {'data': json.dumps(file._asdict()).encode('utf-8')})