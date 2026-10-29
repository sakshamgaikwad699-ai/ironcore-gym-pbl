"""
Database management module for Gym Management System.
Handles SQLite schema creation, foreign key enforcement, dynamic database path
resolution (local vs Vercel /tmp), and initial database seeding with realistic data.
"""

import os
import shutil
import sqlite3
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo
from werkzeug.security import generate_password_hash

IST = ZoneInfo("Asia/Kolkata")


def get_ist_now() -> datetime:
    """Return current datetime in Asia/Kolkata timezone."""
    return datetime.now(IST)


def get_ist_today() -> date:
    """Return current date in Asia/Kolkata timezone."""
    return get_ist_now().date()


def get_db_path() -> str:
    """
    Resolve the SQLite database path based on the host environment.
    On Vercel (serverless lambda), filesystem is read-only except for /tmp.
    On local/PythonAnywhere, gym.db is stored persistently next to app.py.
    """
    if os.environ.get("VERCEL"):
        tmp_db = "/tmp/gym.db"
        bundled_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gym.db")
        # If /tmp/gym.db doesn't exist yet but a pre-seeded gym.db was bundled, copy it
        if not os.path.exists(tmp_db) and os.path.exists(bundled_db):
            try:
                shutil.copyfile(bundled_db, tmp_db)
            except Exception:
                pass
        return tmp_db
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "gym.db")


def get_db_connection() -> sqlite3.Connection:
    """
    Open and return a SQLite connection with foreign keys enabled
    and row factory configured for dictionary-like column access.
    """
    db_path = get_db_path()
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """
    Create tables if they do not exist and seed initial data if empty.
    Never drops or overwrites existing tables or data.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table (Admin authentication)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)

    # 2. Membership Plans Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS membership_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_name TEXT UNIQUE NOT NULL,
            duration_days INTEGER NOT NULL CHECK(duration_days > 0),
            price REAL NOT NULL CHECK(price >= 0),
            description TEXT
        );
    """)

    # 3. Members Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            age INTEGER NOT NULL CHECK(age >= 12 AND age <= 90),
            gender TEXT NOT NULL CHECK(gender IN ('Male', 'Female', 'Other')),
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            registration_date TEXT NOT NULL,
            plan_id INTEGER NOT NULL,
            start_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            FOREIGN KEY(plan_id) REFERENCES membership_plans(id) ON DELETE RESTRICT
        );
    """)

    # 4. Trainers Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trainers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trainer_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            specialization TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            experience INTEGER NOT NULL CHECK(experience >= 0 AND experience <= 50),
            salary REAL NOT NULL CHECK(salary >= 0),
            availability TEXT NOT NULL CHECK(availability IN ('Full-time', 'Part-time'))
        );
    """)

    # 5. Payments Table (CASCADE on member delete)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id TEXT UNIQUE NOT NULL,
            member_id TEXT NOT NULL,
            amount REAL NOT NULL CHECK(amount >= 0),
            payment_method TEXT NOT NULL CHECK(payment_method IN ('Cash', 'UPI', 'Card')),
            payment_date TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Paid', 'Pending')),
            FOREIGN KEY(member_id) REFERENCES members(member_id) ON DELETE CASCADE
        );
    """)

    # 6. Attendance Table (CASCADE on member delete, UNIQUE per member per date)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT NOT NULL,
            attendance_date TEXT NOT NULL,
            check_in_time TEXT NOT NULL,
            FOREIGN KEY(member_id) REFERENCES members(member_id) ON DELETE CASCADE,
            UNIQUE(member_id, attendance_date)
        );
    """)

    # 7. Login Attempts Table (Brute-force protection)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        );
    """)

    # 8. Settings Table (Key-Value store)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)

    # Indexes on frequently searched or filtered columns
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_members_search ON members(member_id, full_name, phone, email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_members_expiry ON members(expiry_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_member ON payments(member_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(payment_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(identifier, attempted_at);")

    conn.commit()

    # Seed data only if the database is currently unpopulated
    cursor.execute("SELECT COUNT(*) AS count FROM users;")
    row = cursor.fetchone()
    if row and row["count"] == 0:
        seed_data(conn)

    conn.close()


def seed_data(conn: sqlite3.Connection) -> None:
    """
    Populate the database with realistic sample data for SPPU B.Tech evaluation.
    Includes default admin, 4 plans, 12 realistic Indian members, 5 trainers,
    20 payments, 7-day attendance, and core gym branding settings.
    """
    cursor = conn.cursor()
    today = get_ist_today()
    now_str = get_ist_now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Default Admin User
    admin_pw_hash = generate_password_hash("password123")
    cursor.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?);",
        ("admin", admin_pw_hash, now_str)
    )

    # 2. Gym Settings
    default_settings = [
        ("gym_name", "IRON CORE FITNESS & ATHLETIC CLUB"),
        ("gym_tagline", "Pune's Premier Strength & Conditioning Facility"),
        ("gym_phone", "+91 98220 12345"),
        ("gym_email", "contact@ironcoregym.in"),
        ("gym_address", "Plot 42, Fergusson College Road, Shivajinagar, Pune - 411005")
    ]
    cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?);", default_settings)

    # 3. Membership Plans
    plans = [
        ("Monthly Plan", 30, 1500.0, "Full gym floor access, locker access, and complimentary fitness assessment."),
        ("Quarterly Plan", 90, 4000.0, "Includes strength floor, cardio deck, steam bath, and 1 trainer orientation."),
        ("Half-Yearly Plan", 180, 7500.0, "Complete access plus diet consultation and 2 personal training vouchers."),
        ("Annual Plan", 365, 13500.0, "All-inclusive VIP membership with unrestricted access, guest passes, and quarterly body composition scans.")
    ]
    cursor.executemany(
        "INSERT INTO membership_plans (plan_name, duration_days, price, description) VALUES (?, ?, ?, ?);",
        plans
    )

    # 4. Trainers (TRN-101 to TRN-105)
    trainers_data = [
        ("TRN-101", "Rajesh Patil", "Strength & Conditioning", "9822100001", "rajesh.patil@ironcoregym.in", 8, 38000.0, "Full-time"),
        ("TRN-102", "Sunita Kulkarni", "Yoga & Mobility", "9822100002", "sunita.k@ironcoregym.in", 5, 30000.0, "Full-time"),
        ("TRN-103", "Vikram Shinde", "CrossFit & Olympic Lifting", "9822100003", "vikram.s@ironcoregym.in", 6, 32000.0, "Full-time"),
        ("TRN-104", "Pooja Deshmukh", "Zumba & Functional Cardio", "9822100004", "pooja.d@ironcoregym.in", 4, 25000.0, "Part-time"),
        ("TRN-105", "Manoj Gokhale", "Bodybuilding & Hypertrophy", "9822100005", "manoj.g@ironcoregym.in", 7, 34000.0, "Part-time")
    ]
    cursor.executemany(
        """INSERT INTO trainers (trainer_id, full_name, specialization, phone, email, experience, salary, availability)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
        trainers_data
    )

    # 5. Members (MEM-1001 to MEM-1012)
    # Mix: 7 Active, 2 Expiring soon (within 7 days), 3 Expired
    members_seed = [
        # (offset_from_today_for_start, offset_from_today_for_expiry, name, age, gender, phone, email, address, plan_id)
        # Active long-term
        (-60, 305, "Rahul Sharma", 24, "Male", "9822011111", "rahul.sharma@gmail.com", "Flat 302, Green Glen, Kothrud, Pune", 4),
        (-30, 60, "Priya Patel", 27, "Female", "9822022222", "priya.patel@yahoo.com", "B-14, Rohan Nilay, Aundh, Pune", 2),
        (-15, 15, "Amit Verma", 29, "Male", "9822033333", "amit.verma@outlook.com", "Row House 7, Nyati Estate, Baner, Pune", 1),
        (-45, 135, "Sneha Kulkarni", 22, "Female", "9822044444", "sneha.k@gmail.com", "Building C, Swapnashilp, Erandwane, Pune", 3),
        (-90, 275, "Vikram Deshmukh", 35, "Male", "9822055555", "vikram.d@gmail.com", "12, Mayur Colony, Kothrud, Pune", 4),
        (-20, 70, "Ananya Joshi", 26, "Female", "9822066666", "ananya.joshi@gmail.com", "Plot 88, Viman Nagar, Pune", 2),
        (-10, 20, "Rohan Patil", 31, "Male", "9822077777", "rohan.patil@rediffmail.com", "B-404, Megapolis, Hinjewadi Phase 3, Pune", 1),
        # Expiring Soon (within 7 days)
        (-27, 3, "Pooja Nair", 28, "Female", "9822088888", "pooja.nair@gmail.com", "Flat 501, Silver Crest, Wakad, Pune", 1),
        (-85, 5, "Aditya Shinde", 33, "Male", "9822099999", "aditya.shinde@gmail.com", "Flat 102, Kapil Malhar, Baner, Pune", 2),
        # Expired
        (-45, -15, "Neha Gupta", 30, "Female", "9890011111", "neha.gupta@gmail.com", "A-12, Kumar Park, Hadapsar, Pune", 1),
        (-110, -20, "Suresh Rao", 45, "Male", "9890022222", "suresh.rao@gmail.com", "Plot 54, Model Colony, Shivajinagar, Pune", 2),
        (-210, -30, "Kavita Mehta", 38, "Female", "9890033333", "kavita.mehta@gmail.com", "B-201, Paranjape Schemes, Karve Nagar, Pune", 3)
    ]

    members_records = []
    payments_records = []
    attendance_records = []

    pay_id_counter = 5001

    for idx, (s_off, e_off, name, age, gender, phone, email, addr, plan_id) in enumerate(members_seed, start=1):
        mem_id = f"MEM-{1000 + idx}"
        start_dt = today + timedelta(days=s_off)
        expiry_dt = today + timedelta(days=e_off)
        reg_dt = start_dt

        members_records.append((
            mem_id, name, age, gender, phone, email, addr,
            reg_dt.isoformat(), plan_id, start_dt.isoformat(), expiry_dt.isoformat()
        ))

        # Plan price mapping
        plan_prices = {1: 1500.0, 2: 4000.0, 3: 7500.0, 4: 13500.0}
        plan_amt = plan_prices.get(plan_id, 1500.0)

        # Primary registration payment
        pay_method = ["UPI", "Card", "Cash"][idx % 3]
        pay_dt = start_dt.isoformat()
        payments_records.append((
            f"PAY-{pay_id_counter}",
            mem_id,
            plan_amt,
            pay_method,
            pay_dt,
            "Paid"
        ))
        pay_id_counter += 1

    # Add extra realistic payments (renewals or pending payments)
    extra_payments = [
        (f"PAY-{pay_id_counter}", "MEM-1001", 13500.0, "UPI", (today - timedelta(days=365)).isoformat(), "Paid"),
        (f"PAY-{pay_id_counter+1}", "MEM-1002", 4000.0, "Card", (today - timedelta(days=120)).isoformat(), "Paid"),
        (f"PAY-{pay_id_counter+2}", "MEM-1005", 13500.0, "UPI", (today - timedelta(days=400)).isoformat(), "Paid"),
        (f"PAY-{pay_id_counter+3}", "MEM-1008", 1500.0, "Cash", (today - timedelta(days=1)).isoformat(), "Pending"),
        (f"PAY-{pay_id_counter+4}", "MEM-1009", 4000.0, "UPI", today.isoformat(), "Paid"),
        (f"PAY-{pay_id_counter+5}", "MEM-1010", 1500.0, "UPI", (today - timedelta(days=46)).isoformat(), "Paid"),
        (f"PAY-{pay_id_counter+6}", "MEM-1011", 4000.0, "Card", (today - timedelta(days=112)).isoformat(), "Paid"),
        (f"PAY-{pay_id_counter+7}", "MEM-1012", 7500.0, "Cash", (today - timedelta(days=212)).isoformat(), "Paid"),
    ]
    payments_records.extend(extra_payments)

    # Insert members
    cursor.executemany(
        """INSERT INTO members (member_id, full_name, age, gender, phone, email, address,
                                registration_date, plan_id, start_date, expiry_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
        members_records
    )

    # Insert payments
    cursor.executemany(
        """INSERT INTO payments (payment_id, member_id, amount, payment_method, payment_date, status)
           VALUES (?, ?, ?, ?, ?, ?);""",
        payments_records
    )

    # 6. Attendance for the last 7 days (today down to today-6)
    active_mems = ["MEM-1001", "MEM-1002", "MEM-1003", "MEM-1004", "MEM-1005", "MEM-1006", "MEM-1007", "MEM-1008", "MEM-1009"]
    checkin_times = ["06:15:00", "06:45:00", "07:10:00", "07:30:00", "08:00:00", "17:30:00", "18:15:00", "19:00:00", "19:45:00"]

    for day_offset in range(7):
        att_dt = today - timedelta(days=day_offset)
        # Pick 5 to 7 members per day
        mems_today = active_mems[day_offset % 3 : (day_offset % 3) + 6]
        for idx, m_id in enumerate(mems_today):
            t_str = checkin_times[(idx + day_offset) % len(checkin_times)]
            attendance_records.append((m_id, att_dt.isoformat(), t_str))

    cursor.executemany(
        """INSERT INTO attendance (member_id, attendance_date, check_in_time)
           VALUES (?, ?, ?);""",
        attendance_records
    )

    conn.commit()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at:", get_db_path())
