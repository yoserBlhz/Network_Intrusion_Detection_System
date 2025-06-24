import sqlite3

def init_db():
    with sqlite3.connect("nids.db") as conn:
        cursor = conn.cursor()
        
        # Check if the table exists and has the old schema
        cursor.execute("PRAGMA table_info(alerts)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if not columns:
            # Create new table with derived features
            cursor.execute("""
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    prediction TEXT,
                    confidence REAL,
                    direction TEXT,
                    protocol_name TEXT,
                    is_internal_src BOOLEAN,
                    is_internal_dst BOOLEAN,
                    country TEXT
                )
            """)
        elif 'direction' not in columns:
            # Add new columns to existing table
            cursor.execute("ALTER TABLE alerts ADD COLUMN direction TEXT")
            cursor.execute("ALTER TABLE alerts ADD COLUMN protocol_name TEXT")
            cursor.execute("ALTER TABLE alerts ADD COLUMN is_internal_src BOOLEAN")
            cursor.execute("ALTER TABLE alerts ADD COLUMN is_internal_dst BOOLEAN")
            cursor.execute("ALTER TABLE alerts ADD COLUMN country TEXT")
        
        # Add live_flows table for ML rule generation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS live_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                proto_num INTEGER,
                port INTEGER,
                packets INTEGER,
                bytes INTEGER,
                first_seen REAL,
                last_seen REAL,
                direction TEXT,
                is_internal_src INTEGER,
                is_internal_dst INTEGER,
                country TEXT
            )
        ''')
        
        conn.commit()

def get_alerts():
    with sqlite3.connect("nids.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, src_ip, dst_ip, prediction, confidence, 
                   direction, protocol_name, is_internal_src, is_internal_dst, country 
            FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT 100
        """)
        return cursor.fetchall()