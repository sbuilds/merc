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

# sqlalchemy
from sqlalchemy import func, case, create_engine, Column, Integer, Numeric, Float, String, DateTime, Text, Boolean, UnicodeText, UniqueConstraint, ForeignKey, Table, or_, and_, distinct, update
from sqlalchemy import UniqueConstraint, Index, text
from sqlalchemy.orm import declarative_base, mapper, scoped_session, sessionmaker, relationship, backref, join, outerjoin, subqueryload
from sqlalchemy.sql import func
from sqlalchemy.orm.exc import MultipleResultsFound
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.postgresql import JSONB, TEXT, NUMERIC, ARRAY, BYTEA
from sqlalchemy.sql.expression import bindparam
from sqlalchemy.sql.schema import Constraint

class DictSerializable:
    def to_dict(self, skipfields=[]):
        import decimal

        result = collections.OrderedDict()

        for key in self.__mapper__.c.keys():
            value = getattr(self, key)
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, decimal.Decimal):
                result[key] = str(value)
            elif key in skipfields:
                continue
            else:
                result[key] = value
        return result

console = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.addHandler(console)
logger.setLevel(os.environ.get('LOG_LEVEL','INFO'))

Base = declarative_base(cls=(DictSerializable,))

class MetaData(Base):
    """ Metadata table:
        Fields: 
        
        id (Integer) - Primary Key
        date_added (DateTime) - datetime the file was added
        file_name (String) 
        file_path (String)
        processed (Boolean) - flag to set if processed
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
            # Index('answer_nameid_rdtype_rdata_cnt', 'name_id', 'rdtype', func.md5('rdata'), unique=True),
            # Index('ix_answer_rdata',func.to_tsvector('english','rdata'), postgresql_using='gin')
    )

    id = Column(Integer, primary_key=True, nullable=False)
    date_added = Column(DateTime(timezone=True), server_default=func.now())
    file_name = Column(String, index=True)
    file_path = Column(String)
    processed = Column(Boolean, default=False)
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
        return (f"<MetaData: id={self.id!r}, date_added={self.date_added!r}, file_name={self.file_name!r}, "
                f"file_path={self.file_path!r}, processed={self.processed!r}, md5={self.md5!r}, sha1={self.sha1!r}, "
                f"sha256={self.sha256!r}, magic={self.magic!r}, file_size={self.file_size!r}, "
                f"imports={self.imports!r}, exports={self.exports!r}, "
                f"header={self.header!r}, header_optional={self.header_optional!r}, "
                f"sections={self.sections!r}, entropy={self.entropy!r}, "
                f"certificates={self.certificates!r}, strings={self.strings!r}>")

# class Load(Base):
#     """
#     """
#     __tablename__ = 'load'

#     id = Column(Integer, primary_key=True, nullable=False)
#     filename = Column(String, nullable=False)
#     filepath = Column(String, nullable=False)

#     def __repr__(self):
#         return (f"<Load: id={self.id}, filename={self.filename}, filepath={self.filepath}>")

def store_files(data) -> None:
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

def store_data(data) -> None:
    logger.info(f"received {len(data)} database records")
    fileids = [x['id'] for x in data]
    logger.info(f"store data id: {fileids}")
    logger.debug(f"param data: {data}")

    insert_stmt = pg_insert(MetaData).values(data)
    update_columns = { k:insert_stmt.excluded[k] for k in data[0].keys() if k != 'id' }
    do_update_stmt = insert_stmt.on_conflict_do_update(index_elements=[MetaData.id], set_=update_columns)

    with session_scope() as session:
        session.execute(do_update_stmt)

postgres_user = os.environ.get('POSTGRES_USER') or 'pguser'
postgres_pass = os.environ.get('POSTGRES_PASSWORD') or 'pguser'
postgres_db = os.environ.get('POSTGRES_DB') or 'merc'

if not postgres_user or not postgres_pass or not postgres_db:
    logger.error(f"Postgres variables not set")
    sys.exit(1)

# engine = create_engine(f"postgresql://{postgres_user}:{postgres_pass}@db/{postgres_db}", echo=False)
engine = create_engine(f"postgresql://{postgres_user}:{postgres_pass}@127.0.0.1/{postgres_db}", echo=False)
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
