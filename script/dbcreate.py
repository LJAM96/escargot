# from sqlaltery import SQLAltery # Not strictly needed if the line is commented
from core import db, stats
from core.conn import Conn
import settings

def main() -> None:
	create_dbs()

def create_dbs() -> None:
	print("DBCREATE: Creating main database tables...")
	conn_db = Conn(settings.DB)
	db.Base.metadata.create_all(conn_db.engine)
	print("DBCREATE: Main database tables creation attempt finished.")

	# print("DBCREATE: Attempting SQLAltery migrations (fake)...")
	# with conn_db.engine.connect() as conn:
	#    SQLAltery('migrations').migrate(conn, fake = True) # Keep this commented
	# print("DBCREATE: SQLAltery migrations attempt finished.")

	print("DBCREATE: Creating stats database tables...")
	conn_stats = Conn(settings.STATS_DB)
	stats.Base.metadata.create_all(conn_stats.engine)
	print("DBCREATE: Stats database tables creation attempt finished.")

if __name__ == '__main__':
	main()