from distutils.log import debug
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

connect_base='postgresql://postgres:new_password@localhost:5432/flask_db'
Base=declarative_base()
engine = create_engine(connect_base)
Session= sessionmaker(bind=engine)