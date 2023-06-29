from behave import fixture
from models.db.transaction import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@fixture
def init_db(context, path="/tmp/soak-tests.db", echo=False):
    engine = create_engine(f"sqlite:///{path}", echo=echo)
    Base.metadata.create_all(engine)
    context.db = engine
    yield context.db


@fixture
def get_db_session(context):
    with Session(context.db) as session:
        yield session
