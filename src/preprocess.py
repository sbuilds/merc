#!/usr/bin/env python3


import argparse
import redis

import database as db



def main():
    parser.add_argument('command', action='store', type=str,
                        help="Command to run")

    args = parser.parse_args()

    p = PEMetaData(args.file)
    print(json.dumps(p.metadata(), indent=2, cls=MyEncoder))
    # print(p.metadata())       

if __name__ == '__main__':

    console = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)

    logger = logging.getLogger('logger')
    logger.addHandler(console)
    logger.setLevel(os.environ.get('LOG_LEVEL','INFO'))

    # client = redis.StrictRedis(host='redis', port=6379, db=0)
    # try: # stream then group
    #     client.xgroup_create('process','process-group', mkstream=True)
    # except redis.exceptions.ResponseError as e:             
    #     logger.exception(f"redis client: {e}")