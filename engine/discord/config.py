import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
raw_id = os.getenv("auth_id", "")
RECIPIENT_IDS = [int(x.strip()) for x in raw_id.split(",")] if raw_id else []


BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # → engine/discord/
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "..", "packets.db"))
TABLE_NAME = "warnings"
KEY_COLUMN = "rowid"