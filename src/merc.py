#!/usr/bin/env python3

__version__ = '0.1'

import filecmp
import os
import sys
import logging
import logging.config
import argparse
import json
import re
from datetime import datetime, date, timedelta
from typing import List, Dict, Callable, Optional, Union, Iterable
from collections import namedtuple
import hashlib
from pathlib import Path
import subprocess

import redis

import pefile
import magic

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from asn1crypto import cms

import database as db

class FileStrings:
    pass

class FileMetaData:
    """
    """

    def __init__(self, id: int, file_name: str, file_path: str) -> None:
        self.database_id = id
        self.filename = file_name
        self.filepath = Path(f"{file_path}/{file_name}")
        self.data = self._open_file()

    def _open_file(self):
        with open(self.filepath, 'rb') as f:
            return f.read()

    def file_size(self):
        return len(self.data)

    def hash(self): 
        hashes = {}

        hashes['md5'] = hashlib.md5(self.data).hexdigest()
        hashes['sha1'] = hashlib.sha1(self.data).hexdigest()
        hashes['sha256'] = hashlib.sha256(self.data).hexdigest()

        return hashes

    def magic(self) -> str:
        """
        python-magic
        libmagic
        """
        return magic.from_file(self.filepath)

    def entropy(self) -> float:
        import math
        counters = {byte: 0 for byte in range(2 ** 8 )}
        for byte in self.data:
            counters[byte] += 1
        # can this be fixed as pa
        filesize = len(self.data)
        # filesize = self.filepath.stat().st_size
        probabilities = [counter / filesize for counter in counters.values()]
        entropy = -sum(probability * math.log2(probability) for probability in probabilities if probability > 0)

        return entropy

class PEMetaData:
    """
    """
    def __init__(self, id: int, file_name: str, file_path: str) -> None:
        self.database_id = id
        self.filename = file_name
        self.filepath = Path(f"{file_path}/{file_name}")
        self.pe = pefile.PE(self.filepath)

    def headers(self) -> Dict:
        headers = {}
        
        headers['number_of_sections'] = self.pe.FILE_HEADER.NumberOfSections

        return headers

    def headers_optional(self) -> Dict:
        headers_optional = {}
        headers_optional['size_of_code'] = self.pe.OPTIONAL_HEADER.SizeOfCode
        headers_optional['size_of_image'] = self.pe.OPTIONAL_HEADER.SizeOfImage
        headers_optional['size_of_stack_reserve'] = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
        headers_optional['size_of_stack_commit'] = self.pe.OPTIONAL_HEADER.SizeOfStackCommit
        headers_optional['size_of_heap_reserve'] = self.pe.OPTIONAL_HEADER.SizeOfHeapReserve
        headers_optional['size_of_heap_commit'] = self.pe.OPTIONAL_HEADER.SizeOfHeapCommit

        return headers_optional

    def sections(self) -> Dict:
        sections = {}
        try:
            pe_sections = self.pe.sections
        except AttributeError as e:
            logger.warning(f"sections: PE parsing failed {e}")
        else:
            for section in pe_sections:
                section_data = {}
                section_data['size_of_raw_data'] = section.SizeOfRawData
                section_data['misc_virtual_size'] = section.Misc_VirtualSize
                section_data['contains_code'] = True if section.Characteristics & 0x00000020 > 0 else False # Contains code
                section_data['executable'] = True if section.Characteristics & 0x20000000 > 0 else False # Contains code
                section_data['writable'] = True if section.Characteristics & 0x80000000 > 0 else False # Contains code
                sections[section.Name.decode('utf-8', errors='ignore').replace('\x00', '')] = section_data
        finally:            
            return sections

    def imports(self) -> List:
        imports = []
        try:
            entries = self.pe.DIRECTORY_ENTRY_IMPORT
        except AttributeError as e:
            print(f"imports: PE parsing failed {e}")
        else:
            for entry in entries:
                for imp in entry.imports: 
                    name = imp.name
                    if name: # imp.name can be NoneType
                        imports.append(name.decode('utf-8', 'ignore'))
        finally:
            return imports

    def exports(self) -> List:
        exports = []
        
        try:
            entries = self.pe.DIRECTORY_ENTRY_EXPORT.symbols
        except AttributeError as e:
            print(f"exports: PE parsing failed {e}")
        else:
            for entry in entries:
                exports.append(entry.name.decode('utf-8', 'ignore'))
        finally:
            return exports

    def cert(self) -> List:
        """
            add x509 extensions
        """
        certificates = []

        try:
            address = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
            size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        except IndexError as e:
            logger.error(f"cert: index error {self.filepath}: {e}")
            return certificates

        if address == 0:
            logger.warning(f"{self.filepath} not signed")
            return certificates

        signature = self.pe.write()[address+8:address+size]
        try:
            pkcs7 = cms.ContentInfo.load(bytes(signature))
        except Exception as e:
            logger.error(f"cert: pkcs7 {self.filepath}: {e}")
        else:
            try:
                pkcs7_certs = pkcs7['content']['certificates']
            except ValueError as e:
                logger.error(f"cert: content info {self.filepath}: {e}")
                return certificates
            else:
                for cert in pkcs7['content']['certificates']:
                    certificate = {}
                    try:
                        parsed_cert = x509.load_der_x509_certificate(cert.dump(), default_backend())
                    except ValueError as e:
                        logger.error(f"cert value error {self.filepath}: {e}")
                        return certificates
                    try:
                        subject = parsed_cert.subject.rfc4514_string()
                    except ValueError as e:
                        logger.error(f"cert: subject invalid {e}")
                    else:
                        certificate['subject'] = dict(re.split(r'(?<!\\)=', s, maxsplit=1) for s in re.split(r'(?<!\\),', subject) if subject)

                    try:
                        issuer = parsed_cert.issuer.rfc4514_string()
                    except ValueError as e:
                        logger.error(f"cert: issuer invalid {e}")
                    else:
                        certificate['issuer'] = dict(re.split(r'(?<!\\)=', i, maxsplit=1) for i in re.split(r'(?<!\\),', issuer) if issuer)

                    certificate['not_before'] = parsed_cert.not_valid_before.isoformat()
                    certificate['not_after'] = parsed_cert.not_valid_after.isoformat()
                    certificate['pub_key'] = parsed_cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, 
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                    certificate['cert'] = parsed_cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
                    certificate['fingerprint'] = parsed_cert.fingerprint(hashes.SHA256()).hex()
                    certificate['serial'] = parsed_cert.serial_number

                    certificates.append(certificate)

        return certificates

    # def metadata(self) -> Dict:
    #     md = {}
    #     md['id'] = self.database_id
    #     md['magic']  = self.magic()
    #     md['file_size'] = self.file_size()
    #     md.update(self.hash())
    #     md['entropy'] = self.entropy()

    #     md['imports'] = self.imports()
    #     md['exports'] = self.exports()
    #     md['headers'] = self.headers()
    #     md['headers_optional'] = self.headers_optional()
    #     md['sections'] = self.sections()
    #     md['certificates'] = self.cert()

    #     return md

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            print(obj)
            return str(obj, encoding='utf-8')
        return json.JSONEncoder.default(self, obj)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('command', action='store', type=str,
                        help="Command to run")
    # parser.add_argument('file', action='store', help="")

    args = parser.parse_args()
    logger.debug(f"args: {args}")

    # p = PEMetaData(args.file)
    # print(json.dumps(p.metadata(), indent=2, cls=MyEncoder))

    if args.command == 'preprocess':
        files = db.read_files()

        for file in files:
            rec_id = client.xadd('process', {'data': json.dumps(file._asdict()).encode('utf-8')})
            logger.debug(f"added {rec_id}: {file.file_path}/{file.file_name} to stream")
            
    if args.command == 'process':
            while True:
                records = client.xreadgroup('process-group','process',{'process':'>'}, count=1)#, noack=True)
                if records:
                    rec_id = records[0][1][0][0].decode('utf-8')
                    logger.debug(f"received message, id: {rec_id}")

                    # data = [json.loads(x[1][b'data'].decode('utf-8')) for x in msg[0][1]]
                    data = json.loads(records[0][1][0][1][b'data'].decode('utf-8'))
                    logger.info(f"received files {data['file_name']}")
                    logger.debug(f"received data: {data}")
                    
                    fmd = FileMetaData(**data)
                    file_data = {}
                    file_data.update({'id':fmd.database_id})
                    file_data.update({'magic':fmd.magic()})
                    file_data.update({'file_size':fmd.file_size()})
                    file_data.update(fmd.hash())
                    file_data.update({'entropy':fmd.entropy()})

                    try:
                        pmd = PEMetaData(**data)
                    except pefile.PEFormatError as e: 
                        logger.error(f"PEFormatError: PE Parsing failed {e}")
                    except AttributeError as e:
                        logger.error(f"AttributeError: PE Parsing failed {e}")
                    else:
                        file_data.update({'imports':pmd.imports()})
                        file_data.update({'exports':pmd.exports()})
                        file_data.update({'headers':pmd.headers()})
                        file_data.update({'headers_optional':pmd.headers_optional()})
                        file_data.update({'sections':pmd.sections()})
                        file_data.update({'certificates':pmd.cert()})
                    
                    rec_id = client.xadd('processed', {'data': json.dumps(file_data)})

                    # client.xdel('process', rec_id)
    
    if args.command == 'process-strings':
        while True:
            records = client.xreadgroup('process-strings-group','process-strings',{'process':'>'}, count=1)
            if records:
                rec_id = records[0][1][0][0].decode('utf-8')
                logger.debug(f"received message, id: {rec_id}")  

                data = json.loads(records[0][1][0][1][b'data'].decode('utf-8'))
                logger.info(f"received files {data['file_name']}")
                logger.debug(f"received data: {data}")      
                path = Path(f"{data['file_path']}/{data['file_name']}")    

                output = subprocess.run(['floss', '-j', '--only=static', str(path)], capture_output=True)
                strings = json.loads(output.stdout)

                data.update({'strings':strings['strings']['static_strings']})
                rec_id = client.xadd('processed', {'data': json.dumps(data)})

    if args.command == 'store':
        while True:
            records = client.xreadgroup('process-group','store',{'processed':'>'}, count=100)
            if records:
                rec_id = records[0][1][0][0].decode('utf-8')
                recs = len(records[0][1])
                logger.debug(f"received {recs} records")
                # print(records)


                data = [json.loads(x[1][b'data'].decode('utf-8')) for x in records[0][1]]
                logger.debug(f"received data: {data}")
                
                try:
                    db.store_data(data)
                except Exception as e:
                    logger.error(f"database save for {[x['id'] for x in data]} failed, {e}")
                else:
                    # pass
                    client.xdel('processed', rec_id)


if __name__ == '__main__':

    console = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)

    logger = logging.getLogger('logger')
    logger.addHandler(console)
    logger.setLevel(os.environ.get('LOG_LEVEL','INFO'))

    client = redis.StrictRedis(host='redis', port=6379, db=0, health_check_interval=30)
    try: # stream then group
        client.xgroup_create('process','process-group', mkstream=True)
    except redis.exceptions.ResponseError as e:             
        logger.info(f"redis client: {e}")

    try:
        client.xgroup_create('processed','process-group', mkstream=True)
    except redis.exceptions.ResponseError as e:             
        logger.info(f"redis client: {e}")
        pass

    try:
        client.xgroup_create('process','process-strings-group', mkstream=True)
    except redis.exceptions.ResponseError as e:             
        logger.info(f"redis client: {e}")
        pass
    main()
