#!/usr/bin/env python3

__version__ = '0.1'

"""
    merc database
"""

import logging
import json
import os
import sys
from typing import List, Dict, Callable, Optional, Union
from datetime import datetime
from contextlib import contextmanager

from sqlalchemy import create_engine, func, Index, UniqueConstraint, ForeignKey
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.orm import declarative_base, mapper, scoped_session, sessionmaker
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.postgresql import JSONB, TEXT, NUMERIC, ARRAY, BYTEA

console = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.addHandler(console)
logger.setLevel(os.environ.get('LOG_LEVEL','INFO'))

Base = declarative_base()

class MetaData(Base):
    """ Metadata table:
        Fields: 
        
        id (Integer) - Primary Key
        date_added (DateTime) - datetime the file was added
        file_name (String) 
        file_path (String)
        md5 (String) - md5 hash of file
        sha1 (String) - sha1 hash of file
        sha256 (String) - sha256 of file
        magic (String) - file header magic
        file_size (Integer) - file size in bytes
        file_entropy (Float) - file entropy value
        imports (Array) - String array of file imports
        exports (Array) - String array of file exports
        pe_header (JSONB) - {machine:, num_of_sections:, timestamp:, }
        sections (JSONB) - [{name: <string>, size: <number>, virt_size: <number>, character: <string>},]
        pe_optional_header (JSONB) - {size_if_code:, size_of_image:, size_of_stack_reserve:, size_of_stack_commit:,
                            size_of_heap_reserve:, size_of_heap_commit:, }
        certificates (JSONB) - File signing certificate info
        strings (Array) - file strings

    """

    __tablename__ = 'metadata'

    __table_args__ = (
    )

    id = Column(Integer, primary_key=True, nullable=False)
    date_added = Column(DateTime(timezone=True), server_default=func.now())
    file_name = Column(String, index=True)
    file_path = Column(String)
    md5 = Column(String, index=True)
    sha1 = Column(String, index=True)
    sha256 = Column(String, index=True)
    magic = Column(String)
    file_size = Column(Integer)
    imports = Column(ARRAY(String))
    exports = Column(ARRAY(String))
    headers = Column(JSONB)
    headers_optional = Column(JSONB)
    sections = Column(JSONB)
    entropy = Column(Float)
    certificates = Column(JSONB)
    strings = Column(ARRAY(String))

    def __repr__(self):
        return (f"<MetaData: id={self.id!r}, "
                f"date_added={self.date_added!r}, "
                f"file_name={self.file_name!r}, "
                f"file_path={self.file_path!r}, "
                f"md5={self.md5!r}, sha1={self.sha1!r}, "
                f"sha256={self.sha256!r}, "
                f"magic={self.magic!r}, "
                f"file_size={self.file_size!r}, "
                f"imports={self.imports!r}, "
                f"exports={self.exports!r}, "
                f"header={self.header!r}, "
                f"header_optional={self.header_optional!r}, "
                f"sections={self.sections!r}, "
                f"entropy={self.entropy!r}, "
                f"certificates={self.certificates!r}, "
                f"strings={self.strings!r}>")

def store_files(data: List) -> None:
    logger.debug(f"recieved {len(data)} files")

    keys = ['file_path','file_name']
    insert_records = [dict(zip(keys,[str('/samples'), x.name])) for x in data]
    insert_stmt = pg_insert(MetaData).values(insert_records)
    logger.debug(f"files db insert: {insert_stmt}")

    with session_scope() as session:
        session.execute(insert_stmt)

def read_files() -> Dict:
    with session_scope() as session:
        records = session.query(MetaData.id, MetaData.file_name, MetaData.file_path).all()
    return records

def store_data(data: List) -> None:
    logger.info(f"received {len(data)} database records")
    fileids = [x['id'] for x in data]
    logger.info(f"store data id: {fileids}")
    logger.debug(f"param data: {data}")

    insert_stmt = pg_insert(MetaData).values(data)
    update_columns = { k:insert_stmt.excluded[k] for k in data[0].keys() if k != 'id' }
    do_update_stmt = insert_stmt.on_conflict_do_update(index_elements=[MetaData.id], set_=update_columns)
    logger.debug(f"sotre data stmt: {do_update_stmt}")

    with session_scope() as session:
        session.execute(do_update_stmt)

postgres_user = os.environ.get('POSTGRES_USER')
postgres_pass = os.environ.get('POSTGRES_PASSWORD')
postgres_db = os.environ.get('POSTGRES_DB')
postgres_host = os.environ.get('POSTGRES_HOST')

if not postgres_user or not postgres_pass or not postgres_db:
    logger.error(f"Postgres variables not set")
    sys.exit(1)

engine = create_engine(f"postgresql://{postgres_user}:{postgres_pass}@{postgres_host}/{postgres_db}", echo=False, future=True)
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker())
Session.configure(bind=engine)

@contextmanager
def session_scope() -> Session:
    """Provide a transactional scope around a series of operations."""
    session = Session()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()
