#!/usr/bin/env python3

import argparse
import json
import redis
import logging
import os


import database as db

# parser = argparse.ArgumentParser()
# parser.add_argument('path', metavar='PATH', action='store', help="")
# args = parser.parse_args()

logging.getLogger().setLevel(os.environ.get('LOGGING_LEVEL','INFO'))
logger = logging.getLogger(__name__)

files = db.read_files()
# print(files)
client = redis.StrictRedis(host='127.0.0.1', port=6379, db=0)
try:
    client.xgroup_create('process','process-group', mkstream=True)
except redis.exceptions.ResponseError as e:
    logger.warning(f"redis client: {e}")
for file in files:
    # print(file.file_name)
    # rec_id = client.xadd('process', {'data': json.dumps([ row._asdict() for row in files]).encode('utf-8')})
    # if file.file_name == '457227':
        # print(file)
    rec_id = client.xadd('process', {'data': json.dumps(file._asdict()).encode('utf-8')})

# msg = client.xreadgroup('process-group','preprocess',{'process':'>'}, count=1, block=0, noack=True)
# print(msg[0][1][0][1][b'data'].decode())
# print(msg)