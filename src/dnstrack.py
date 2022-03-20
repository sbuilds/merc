#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# gevent imports and patching
import gevent.monkey
gevent.monkey.patch_all(time=True)
from gevent.pool import Pool

import os
import sys
import collections
import logging
import logging.config
import argparse
import json
import time
import itertools
from datetime import datetime, date, timedelta
from typing import List, Dict, Callable, Optional, Union, Iterable


# additonal imports
import dns.resolver
import dns.reversename
import redis
from cron_validator import CronValidator

from sqlalchemy import cast, Date, or_, and_

# local imports
import database as db

def name_lookup(records: List[db.Name], resolver_timeout: int = 5, pool_size: int = 500) -> None:
    resolver = dns.resolver.Resolver()
    resolver.timeout = resolver_timeout
    resolver.lifetime = resolver_timeout
    # resolver.nameservers = ['8.8.8.8','8.4.4.8']

    def lookup(name: str, rdtypes: Optional[List[str]] = None) -> None:
        rdtypes = ['A','AAAA','AFSDB','APL','CAA','CDNSKEY','CDS','CERT','CNAME','CSYNC','DHCID','DLV','DNAME','DNSKEY','DS','EUI48','EUI64','HINFO','HIP','HTTPS','IPSECKEY','KEY','KX','LOC','MX','NAPTR','NS','NSEC','NSEC3','NSEC3PARAM','OPENPGPKEY','PTR','RRSIG','RP','SIG','SMIMEA','SOA','SRV','SSHFP','SVCB','TA','TKEY','TLSA','TSIG','TXT','URI','ZONEMD']
        if not rdtypes:
            rdtypes = ['A']

        for rdtype in rdtypes:
            data = collections.defaultdict(dict)
            try:
                answers = resolver.query(name, rdtype)
            except dns.resolver.NXDOMAIN:
                logger2.warning(f"{name}: {rdtype}: NX Domain")
            except dns.resolver.NoAnswer:
                logger2.warning(f"{name}: {rdtype}: No Data")
            except dns.resolver.Timeout:
                logger2.warning(f"{name}: {rdtype}: Timeout")
            except dns.exception.DNSException:
                logger2.warning(f"{name}: {rdtype}: DNS exception")
            else:
                data[name][rdtype] = [rdata.to_text() for rdata in answers.rrset]
                logger2.info(f"Received DNS for {name}")
                status = client.xadd('dnstrack-lookup', {'data':json.dumps(data).encode('utf-8')})
                logger.debug("redis xadd status: {status}".format(status=status))
    
    pool = Pool(pool_size)
    for rec in records:
        logger.debug(f"lookup rec: {rec}")
        if rec['rec_type'] == 'd': # domain fwd lookup
            rdtypes = ['A', 'AAAA', 'TXT', 'MX', 'NS', 'CNAME']
            pool.spawn(lookup, rec['name'], rdtypes)
        if rec['rec_type'] == '4' or rec['rec_type'] == '6':
            rdtypes = ['PTR']
            pool.spawn(lookup, dns.reversename.from_address(rec['name']), rdtypes)

    pool.join()

def chunker(iterable: Iterable, size: int = 1000) -> List:
    iterator = iter(iterable)
    chunk = list(itertools.islice(iterator, size))

    while len(chunk) == size:
        yield chunk
        chunk = list(itertools.islice(iterator, size))

    yield chunk

def add_names(infile: Optional[str] = None, names: Optional[List[str]] = None) -> None:
    if infile:
        with open(infile) as f:
            for name in chunker(f, 10000):
                db.add_name(name)
    else:
        for name in names:
            db.add_name(name)

def gen_cron() -> str:
    now = datetime.utcnow()
    return f"{now.minute} {now.hour} {now.day} {now.month} {now.weekday()+1}"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', action='store', type=str,
                            help="")
    parser.add_argument('-m', '--minute', dest='cron', action='append',type=str,
                            help="")
    parser.add_argument('-o', '--hour', dest='cron', action='append',type=str,
                            help="")
    parser.add_argument('-d', '--day', dest='cron', action='append',type=str,
                            help="")
    parser.add_argument('-n', '--month', dest='cron', action='append',type=str,
                            help="")
    parser.add_argument('-w', '--dayofweek', dest='cron', action='append',type=str,
                            help="")
    parser.add_argument('-s', '--cron-string', dest='cron_string', action='store', type=str,
                            help="eg: '0 1 * * *'")
    parser.add_argument('--now', dest='cron_string', action='store_const', const=gen_cron())
    parser.add_argument('--dt', dest='dt', action='store_const', const=datetime.utcnow())

    # Evnvironment Arguments
    parser.add_argument('--resolver-timeout', dest='resolver_timeout', action='store', type=int,
                    default=5, help="timeout in secs on dns resolution")
    parser.add_argument('--pool-size', dest='pool_size', action='store', type=int, 
                    default=os.environ.get('POOL_SIZE', 500))
    parser.add_argument('--lookup-count', dest='lookup_count', action='store', type=int,
                    default=os.environ.get('LOOKUP_COUNT', 10000))
    parser.add_argument('--check-count', dest='check_count', action='store', type=int,
                    default=os.environ.get('CHECK_COUNT', 100000))
    parser.add_argument('--store-count', dest='store_count', action='store', type=int,
                    default=os.environ.get('STORE_COUNT', 1000))

    parser.add_argument('-f','--infile', dest='infile', action='store',
                    help="FILE - domain list", metavar='FILE')

    args = parser.parse_args()
    logger.debug(f"args: {args}")

    if args.infile:
        add_names(infile=args.infile)
        sys.exit()

    if args.command == 'lookup':
        while True:
            msg = client.xreadgroup('con-group','lookup',{'dnstrack':'>'}, count=args.lookup_count, block=0, noack=True)
            if msg:
                msg_id = msg[0][1][0][0].decode('utf-8')
                logger.debug(f"received message, id: {msg_id}")

                data = [json.loads(x[1][b'data'].decode('utf-8')) for x in msg[0][1]]
                logger.debug(f"received data: {data}")
                
                logger.info(f"MARK: received {len(data)} records")
                name_lookup(data, pool_size=args.pool_size)

    if args.command == 'check' and args.dt:
        with db.session_scope() as session:
            result = session.query(db.Schedule).all()
            schedule_ids = [rec.id for rec in result if CronValidator.match_datetime(rec.cron_string, args.dt)]
            
            for rec in session.query(db.Name).filter(db.Name.schedule_id.in_(schedule_ids)).yield_per(args.check_count).order_by(db.Name.id):
                logger.debug(f"redis xadd {rec.to_dict()}")
                status = client.xadd('dnstrack', {'data':json.dumps(rec.to_dict()).encode('utf-8')})
                logger.debug("redis xadd status: {status}".format(status=status))
                logger.info(f"added {rec.name} to stream")

    if args.command == 'store':
        while True:
            msg = client.xreadgroup('con-group','store',{'dnstrack-lookup':'>'}, count=1000, block=0, noack=True)
            if msg:
                msg_id = msg[0][1][0][0].decode('utf-8')
                logger.debug(f"received message, id: {msg_id}")

                data = [json.loads(x[1][b'data'].decode('utf-8')) for x in msg[0][1]]
                logger.debug(f"received data: {data}")
            
                logger.info(f"received {len(data)} records")
                db.store_dns_data_bulk(data)

if __name__ == '__main__':

    console = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)

    logger = logging.getLogger('logger')
    logger.addHandler(console)
    logger.setLevel(os.environ.get('LOG_LEVEL','INFO'))

    logger2 = logging.getLogger('logger2')
    logger2.addHandler(console)
    logger2.setLevel(os.environ.get('LOG_LEVEL2','INFO'))

    # redis 
    client = redis.StrictRedis(host='redis', port=6379, db=0)
    try:
        client.xgroup_create('dnstrack','con-group', mkstream=True)
    except redis.exceptions.ResponseError as e:             
        logger2.warning(f"redis client: {e}")
        pass

    try:
        client.xgroup_create('dnstrack-lookup','con-group', mkstream=True)
    except redis.exceptions.ResponseError as e:             
        logger2.warning(f"redis client: {e}")
        pass

    main()








