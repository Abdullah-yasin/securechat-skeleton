import os
import pymysql
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


def get_connection():
    """
    Return a new PyMySQL connection using environment variables.

    Required env vars:
      DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
    """
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASSWORD", "")
    db_name = os.getenv("DB_NAME", "securechat")

    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )
