# db.py
import sqlite3
import os

DB_FILE = "cybertrace.db"


def get_connection():
    """Open a connection to the SQLite database file."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row   # lets us use column names later
    return conn


def init_db():
    """Create the transactions table with all columns."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp TEXT NOT NULL,
            tx_type TEXT NOT NULL DEFAULT 'Transfer',
            location TEXT NOT NULL DEFAULT 'Unknown'
        )
    """)
    conn.commit()
    conn.close()


def insert_transaction(sender, receiver, amount, timestamp, tx_type="Transfer", location="Unknown"):
    """Insert one transaction and return its new id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO transactions
           (sender, receiver, amount, timestamp, tx_type, location)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sender, receiver, amount, timestamp, tx_type, location),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_all_transactions():
    """Return every transaction as a list of dicts."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY id")
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def count_transactions():
    """Return how many transactions exist."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM transactions")
    c = cur.fetchone()["c"]
    conn.close()
    return c

def get_transactions_grouped_by_pair():
    """
    Return dict: {(sender, receiver): [list of transactions]}.
    Used by rapid-repeat detection.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY timestamp")
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()

    pairs = {}
    for tx in rows:
        key = (tx["sender"], tx["receiver"])
        pairs.setdefault(key, []).append(tx)
    return pairs


def get_transactions_grouped_by_pair_bidirectional():
    """
    Return dict with symmetric keys, so A->B and B->A are grouped together.
    Used by circular-pair detection.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY timestamp")
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()

    pairs = {}
    for tx in rows:
        key = tuple(sorted([tx["sender"], tx["receiver"]]))
        pairs.setdefault(key, []).append(tx)
    return pairs


if __name__ == "__main__":
    # Running `python db.py` will initialize the DB and print a summary.
    init_db()
    print("Database ready:", os.path.abspath(DB_FILE))
    print("Current row count:", count_transactions())