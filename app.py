"""
================================================================================
IRON CORE GYM MANAGEMENT SYSTEM - MAIN APPLICATION
SPPU Pune - B.Tech AI & Data Science PBL Coursework
Tech Stack: HTML5, CSS3, Python 3.11+ (Flask), SQLite3
Strict Architecture: Zero JavaScript, Pure Server-Side Processing
================================================================================
"""

import csv
import functools
import hmac
import io
import os
import re
import secrets
from datetime import date, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

import database

# ==============================================================================
# SECTION 1: CONFIGURATION & APPLICATION SETUP
# ==============================================================================

app = Flask(__name__)

# Cryptographic Secret Key for signed session cookies
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Enhanced Cookie Security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True when SSL/HTTPS is active

# Timezone standard: Asia/Kolkata (IST)
IST = ZoneInfo("Asia/Kolkata")


def get_now_ist() -> datetime:
    """Return the current datetime strictly in the Asia/Kolkata timezone."""
    return datetime.now(IST)


def get_today_ist() -> date:
    """Return the current calendar date strictly in the Asia/Kolkata timezone."""
    return get_now_ist().date()


# Ensure the database tables and sample records are initialized
with app.app_context():
    database.init_db()

# ==============================================================================
# SECTION 2: DATABASE LIFECYCLE (ONE CONNECTION PER REQUEST)
# ==============================================================================


def get_db():
    """
    Retrieve or initialize the SQLite database connection for the current request.
    Foreign key enforcement is enabled on every single connection.
    """
    if "db" not in g:
        g.db = database.get_db_connection()
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Safely close the request-scoped database connection when tearing down."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_db(query: str, args: tuple = (), one: bool = False):
    """
    Execute a parameterized SQL query and return SQLite Row objects.
    Guarantees parameterized query execution with '?' placeholders.
    """
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def get_gym_setting(key: str, default: str = "") -> str:
    """Retrieve a setting value from the settings key-value store."""
    row = query_db("SELECT value FROM settings WHERE key = ?;", (key,), one=True)
    return row["value"] if row else default


# ==============================================================================
# SECTION 3: JINJA2 CUSTOM FILTERS & TEMPLATE GLOBALS
# ==============================================================================


@app.template_filter("format_currency")
def format_currency_filter(amount) -> str:
    """
    Format numeric currency into Indian Rupee representation (e.g., ₹1,500.00).
    """
    if amount is None or amount == "":
        return "₹0.00"
    try:
        val = float(amount)
        return f"₹{val:,.2f}"
    except (ValueError, TypeError):
        return f"₹{amount}"


@app.template_filter("format_date")
def format_date_filter(iso_date_str: str) -> str:
    """
    Format ISO YYYY-MM-DD date strings into human-readable Indian DD-MM-YYYY format.
    """
    if not iso_date_str:
        return "—"
    try:
        # Handles both YYYY-MM-DD and YYYY-MM-DD HH:MM:SS
        parts = str(iso_date_str).split(" ")[0].split("-")
        if len(parts) == 3:
            return f"{parts[2]}-{parts[1]}-{parts[0]}"
        return str(iso_date_str)
    except Exception:
        return str(iso_date_str)


def generate_csrf_token() -> str:
    """
    Return or create a secure per-session CSRF token using secrets.token_urlsafe.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


# Register CSRF token callable in Jinja templates globally
app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.context_processor
def inject_global_template_data() -> Dict[str, Any]:
    """Inject common branding and current IST dates into all rendered templates."""
    today = get_today_ist()
    gym_name = get_gym_setting("gym_name", "IRON CORE FITNESS & ATHLETIC CLUB")
    return {
        "gym_name": gym_name,
        "today_iso": today.isoformat(),
        "today_formatted": today.strftime("%d-%m-%Y"),
    }


# ==============================================================================
# SECTION 4: SECURITY HEADERS & CSRF VERIFICATION
# ==============================================================================


@app.before_request
def verify_csrf_token():
    """
    Hand-crafted CSRF Protection:
    On every state-modifying POST request, verify the submitted token against
    the session token using constant-time string comparison (hmac.compare_digest).
    Aborts with HTTP 400 Bad Request on failure.
    """
    if request.method == "POST":
        # Extract CSRF token from form payload
        client_token = request.form.get("csrf_token")
        server_token = session.get("csrf_token")

        if not client_token or not server_token:
            abort(400, description="CSRF token missing from form submission.")

        # Constant-time comparison prevents timing attacks
        if not hmac.compare_digest(str(client_token), str(server_token)):
            abort(400, description="CSRF token validation failed. Submission rejected.")


@app.after_request
def apply_security_headers(response: Response) -> Response:
    """
    Apply strict HTTP response security headers.
    Content-Security-Policy disallows all JavaScript scripts ('none').
    Allows inline styles for the pure-CSS attendance bar chart width calculation.
    """
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'none'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ==============================================================================
# SECTION 5: AUTHENTICATION & ACCESS CONTROL
# ==============================================================================


def login_required(view_func: Callable) -> Callable:
    """
    Decorator requiring active administrator session for route access.
    Redirects unauthenticated requests to /login with a safe relative 'next' URL.
    """
    @functools.wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("logged_in"):
            safe_next = request.full_path if request.method == "GET" else url_for("dashboard")
            return redirect(url_for("login", next=safe_next))
        return view_func(*args, **kwargs)

    return wrapped_view


def is_safe_redirect_url(target: Optional[str]) -> bool:
    """Verify that a redirect destination is strictly a local relative path."""
    if not target:
        return False
    parsed = urlparse(target)
    # Ensure no external scheme/netloc and starts with single slash
    return not parsed.netloc and not parsed.scheme and target.startswith("/") and not target.startswith("//")


def is_login_locked(username: str) -> bool:
    """
    Check if a username has triggered brute-force protection.
    Condition: >= 5 failed login attempts in the preceding 10 minutes.
    """
    ten_mins_ago = (get_now_ist() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    row = query_db(
        "SELECT COUNT(*) AS failed_count FROM login_attempts WHERE identifier = ? AND attempted_at >= ?;",
        (username, ten_mins_ago),
        one=True,
    )
    return row["failed_count"] >= 5 if row else False


def record_failed_login(username: str):
    """Log a failed authentication attempt with IST timestamp."""
    now_str = get_now_ist().strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (identifier, attempted_at) VALUES (?, ?);",
        (username, now_str),
    )
    db.commit()


def clear_failed_logins(username: str):
    """Remove failed login logs upon successful admin authentication."""
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE identifier = ?;", (username,))
    db.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Administrator authentication portal.
    Features Werkzeug hash verification, brute-force throttling, and safe redirects.
    """
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    next_url = request.args.get("next") or request.form.get("next") or ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 1. Check Brute-Force Lockout
        if is_login_locked(username):
            flash(
                "Account temporarily locked due to 5 consecutive failed login attempts. "
                "Please wait 10 minutes before trying again.",
                "danger",
            )
            return render_template("login.html", next_url=next_url)

        # 2. Query user from database
        user = query_db("SELECT * FROM users WHERE username = ?;", (username,), one=True)

        if user and check_password_hash(user["password_hash"], password):
            # Successful authentication
            session.clear()
            session["logged_in"] = True
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            # Generate new per-session CSRF token upon login
            generate_csrf_token()

            clear_failed_logins(username)
            flash(f"Welcome back, {user['username']}! Authenticated successfully.", "success")

            if next_url and is_safe_redirect_url(next_url):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        else:
            record_failed_login(username)
            flash("Invalid administrator credentials. Please check username and password.", "danger")

    return render_template("login.html", next_url=next_url)


@app.route("/logout")
def logout():
    """Clear administrator session and return to login page."""
    session.clear()
    flash("You have been signed out of the system.", "info")
    return redirect(url_for("login"))


# ==============================================================================
# SECTION 6: EXECUTIVE DASHBOARD
# ==============================================================================


@app.route("/")
@login_required
def dashboard():
    """
    Real-time administrative operations overview.
    Computes live aggregates and highlights upcoming membership expirations.
    """
    today = get_today_ist()
    today_iso = today.isoformat()
    month_start_iso = today.replace(day=1).isoformat()
    seven_days_later_iso = (today + timedelta(days=7)).isoformat()

    # 1. Total Members
    m_row = query_db("SELECT COUNT(*) AS total FROM members;", one=True)
    total_members = m_row["total"] if m_row else 0

    # 2. Active Members (expiry_date >= today)
    act_row = query_db(
        "SELECT COUNT(*) AS active_count FROM members WHERE expiry_date >= ?;",
        (today_iso,),
        one=True,
    )
    active_members = act_row["active_count"] if act_row else 0

    # 3. Expired Members (expiry_date < today)
    exp_row = query_db(
        "SELECT COUNT(*) AS exp_count FROM members WHERE expiry_date < ?;",
        (today_iso,),
        one=True,
    )
    expired_members = exp_row["exp_count"] if exp_row else 0

    # 4. Total Trainers
    trn_row = query_db("SELECT COUNT(*) AS total_trn FROM trainers;", one=True)
    total_trainers = trn_row["total_trn"] if trn_row else 0

    # 5. Total Revenue (Paid)
    rev_row = query_db(
        "SELECT COALESCE(SUM(amount), 0.0) AS total_rev FROM payments WHERE status = 'Paid';",
        one=True,
    )
    total_revenue = rev_row["total_rev"] if rev_row else 0.0

    # 6. This-Month Revenue (Paid)
    mrev_row = query_db(
        "SELECT COALESCE(SUM(amount), 0.0) AS month_rev FROM payments WHERE status = 'Paid' AND payment_date >= ?;",
        (month_start_iso,),
        one=True,
    )
    month_revenue = mrev_row["month_rev"] if mrev_row else 0.0

    # 7. Today's Attendance
    att_row = query_db(
        "SELECT COUNT(*) AS att_today FROM attendance WHERE attendance_date = ?;",
        (today_iso,),
        one=True,
    )
    today_attendance = att_row["att_today"] if att_row else 0

    # 8. Members expiring in <= 7 days (and still >= today)
    expiring_rows = query_db(
        """SELECT m.member_id, m.full_name, m.phone, m.expiry_date, p.plan_name
           FROM members m
           JOIN membership_plans p ON m.plan_id = p.id
           WHERE m.expiry_date >= ? AND m.expiry_date <= ?
           ORDER BY m.expiry_date ASC;""",
        (today_iso, seven_days_later_iso),
    )

    expiring_members = []
    for r in expiring_rows:
        exp_dt = date.fromisoformat(r["expiry_date"])
        days_left = (exp_dt - today).days
        expiring_members.append({
            "member_id": r["member_id"],
            "full_name": r["full_name"],
            "phone": r["phone"],
            "expiry_date": r["expiry_date"],
            "plan_name": r["plan_name"],
            "days_left": days_left,
        })

    # 9. Latest 5 Registered Members
    recent_members = query_db(
        """SELECT m.member_id, m.full_name, m.registration_date, m.expiry_date, p.plan_name
           FROM members m
           JOIN membership_plans p ON m.plan_id = p.id
           ORDER BY m.id DESC LIMIT 5;"""
    )

    stats = {
        "total_members": total_members,
        "active_members": active_members,
        "expired_members": expired_members,
        "total_trainers": total_trainers,
        "total_revenue": total_revenue,
        "month_revenue": month_revenue,
        "today_attendance": today_attendance,
    }

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        expiring_members=expiring_members,
        recent_members=recent_members,
        current_month_name=today.strftime("%B %Y"),
    )


# ==============================================================================
# SECTION 7: MEMBERS CRUD, SEARCH, FILTERS & RENEWAL
# ==============================================================================


def generate_next_member_id() -> str:
    """
    Generate sequential member identifier based on MAX numeric suffix.
    Guarantees MEM-1001, MEM-1002, etc. (never relies on row count).
    """
    row = query_db(
        "SELECT MAX(CAST(SUBSTR(member_id, 5) AS INTEGER)) AS max_id FROM members WHERE member_id LIKE 'MEM-%';",
        one=True,
    )
    next_num = (row["max_id"] + 1) if (row and row["max_id"]) else 1001
    return f"MEM-{next_num}"


@app.route("/members")
@login_required
def members_list():
    """
    Searchable, filterable, and paginated roster of club members.
    Pagination and active search filters are preserved across page navigations.
    """
    search_query = request.args.get("q", "").strip()
    selected_plan = request.args.get("plan", "").strip()
    selected_status = request.args.get("status", "").strip()
    selected_sort = request.args.get("sort", "newest").strip()

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 10
    offset = (page - 1) * per_page

    today = get_today_ist()
    today_iso = today.isoformat()

    # Build SQL dynamically with strictly parameterized values
    where_clauses = ["1=1"]
    params: List[Any] = []

    if search_query:
        where_clauses.append(
            "(m.full_name LIKE ? OR m.member_id LIKE ? OR m.phone LIKE ? OR m.email LIKE ?)"
        )
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term, like_term])

    if selected_plan:
        where_clauses.append("m.plan_id = ?")
        params.append(selected_plan)

    if selected_status == "active":
        where_clauses.append("m.expiry_date >= ?")
        params.append(today_iso)
    elif selected_status == "expired":
        where_clauses.append("m.expiry_date < ?")
        params.append(today_iso)

    where_sql = " AND ".join(where_clauses)

    # Sorting options
    sort_orders = {
        "newest": "m.id DESC",
        "oldest": "m.id ASC",
        "name_asc": "m.full_name ASC",
        "name_desc": "m.full_name DESC",
        "expiry_asc": "m.expiry_date ASC",
        "expiry_desc": "m.expiry_date DESC",
    }
    order_by_sql = sort_orders.get(selected_sort, "m.id DESC")

    # Get total count for pagination
    count_query = f"SELECT COUNT(*) AS total FROM members m WHERE {where_sql};"
    count_row = query_db(count_query, tuple(params), one=True)
    total_count = count_row["total"] if count_row else 0
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    # Fetch paginated members
    members_query = f"""
        SELECT m.id, m.member_id, m.full_name, m.age, m.gender, m.phone, m.email,
               m.registration_date, m.start_date, m.expiry_date, p.plan_name
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        WHERE {where_sql}
        ORDER BY {order_by_sql}
        LIMIT ? OFFSET ?;
    """
    query_params = list(params) + [per_page, offset]
    rows = query_db(members_query, tuple(query_params))

    members = []
    for r in rows:
        exp_dt = date.fromisoformat(r["expiry_date"])
        days_left = (exp_dt - today).days
        members.append({
            "id": r["id"],
            "member_id": r["member_id"],
            "full_name": r["full_name"],
            "age": r["age"],
            "gender": r["gender"],
            "phone": r["phone"],
            "email": r["email"],
            "registration_date": r["registration_date"],
            "start_date": r["start_date"],
            "expiry_date": r["expiry_date"],
            "plan_name": r["plan_name"],
            "days_left": days_left,
        })

    plans = query_db("SELECT id, plan_name FROM membership_plans ORDER BY price ASC;")

    return render_template(
        "members.html",
        active_page="members",
        members=members,
        plans=plans,
        total_count=total_count,
        total_pages=total_pages,
        current_page=page,
        search_query=search_query,
        selected_plan=selected_plan,
        selected_status=selected_status,
        selected_sort=selected_sort,
    )


@app.route("/members/add", methods=["GET", "POST"])
@login_required
def member_add():
    """
    Enroll a new member.
    Server-side validation ensures phone formatting, age limits, and auto-calculates
    expiry date: start_date + timedelta(days=plan.duration_days).
    """
    plans = query_db("SELECT id, plan_name, duration_days, price FROM membership_plans ORDER BY price ASC;")

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        age_str = request.form.get("age", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        plan_id_str = request.form.get("plan_id", "").strip()
        start_date_str = request.form.get("start_date", "").strip()

        errors = []

        if not full_name:
            errors.append("Full Name is mandatory.")
        try:
            age = int(age_str)
            if age < 12 or age > 90:
                errors.append("Member age must be between 12 and 90 years.")
        except ValueError:
            errors.append("Age must be a valid whole number.")

        if gender not in ("Male", "Female", "Other"):
            errors.append("Please specify a valid gender category.")

        if not re.match(r"^[6-9]\d{9}$", phone):
            errors.append("Phone must be a valid 10-digit Indian mobile number starting with 6, 7, 8, or 9.")

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors.append("Please provide a valid email address.")

        if not address:
            errors.append("Residential address is required.")

        selected_plan = None
        try:
            plan_id = int(plan_id_str)
            selected_plan = query_db(
                "SELECT id, duration_days, price FROM membership_plans WHERE id = ?;",
                (plan_id,),
                one=True,
            )
            if not selected_plan:
                errors.append("Selected membership package does not exist.")
        except ValueError:
            errors.append("Invalid membership plan selected.")

        try:
            start_dt = date.fromisoformat(start_date_str)
        except ValueError:
            errors.append("Start date must be in valid YYYY-MM-DD format.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template(
                "add_member.html",
                active_page="members",
                plans=plans,
                form_data=request.form,
            )

        # Expiry date = start_date + plan duration in days
        expiry_dt = start_dt + timedelta(days=selected_plan["duration_days"])
        member_id = generate_next_member_id()
        reg_date = get_today_ist().isoformat()

        db = get_db()
        db.execute(
            """INSERT INTO members (member_id, full_name, age, gender, phone, email, address,
                                    registration_date, plan_id, start_date, expiry_date)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            (
                member_id,
                full_name,
                age,
                gender,
                phone,
                email,
                address,
                reg_date,
                selected_plan["id"],
                start_dt.isoformat(),
                expiry_dt.isoformat(),
            ),
        )
        db.commit()

        flash(
            f"Athlete {full_name} enrolled successfully with ID {member_id}! "
            f"Membership active until {expiry_dt.strftime('%d-%m-%Y')}.",
            "success",
        )
        return redirect(url_for("member_details", member_id=member_id))

    return render_template(
        "add_member.html",
        active_page="members",
        plans=plans,
        form_data={},
    )


@app.route("/members/<member_id>")
@login_required
def member_details(member_id: str):
    """
    Detailed dossier for an individual member.
    Shows profile info, active subscription status, payments ledger, and attendance history.
    """
    member = query_db(
        """SELECT m.*, p.plan_name, p.duration_days, p.price AS plan_price
           FROM members m
           JOIN membership_plans p ON m.plan_id = p.id
           WHERE m.member_id = ?;""",
        (member_id,),
        one=True,
    )
    if not member:
        abort(404)

    today = get_today_ist()
    exp_dt = date.fromisoformat(member["expiry_date"])
    is_active = member["expiry_date"] >= today.isoformat()
    days_left = (exp_dt - today).days if is_active else 0
    days_ago = (today - exp_dt).days if not is_active else 0

    payments = query_db(
        """SELECT payment_id, amount, payment_method, payment_date, status
           FROM payments
           WHERE member_id = ?
           ORDER BY payment_date DESC, id DESC;""",
        (member_id,),
    )

    attendance = query_db(
        """SELECT attendance_date, check_in_time
           FROM attendance
           WHERE member_id = ?
           ORDER BY attendance_date DESC, id DESC;""",
        (member_id,),
    )

    return render_template(
        "member_details.html",
        active_page="members",
        member=member,
        is_active=is_active,
        days_left=days_left,
        days_ago=days_ago,
        payments=payments,
        attendance=attendance,
    )


@app.route("/members/<member_id>/edit", methods=["GET", "POST"])
@login_required
def member_edit(member_id: str):
    """
    Edit existing member demographic or subscription details.
    Allows manual or automated expiry date recalculation.
    """
    member = query_db("SELECT * FROM members WHERE member_id = ?;", (member_id,), one=True)
    if not member:
        abort(404)

    plans = query_db("SELECT id, plan_name, duration_days, price FROM membership_plans ORDER BY price ASC;")

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        age_str = request.form.get("age", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        plan_id_str = request.form.get("plan_id", "").strip()
        start_date_str = request.form.get("start_date", "").strip()
        expiry_date_str = request.form.get("expiry_date", "").strip()
        recalc_expiry = request.form.get("recalc_expiry") == "1"

        errors = []
        if not full_name:
            errors.append("Full Name cannot be empty.")
        try:
            age = int(age_str)
            if age < 12 or age > 90:
                errors.append("Age must be between 12 and 90.")
        except ValueError:
            errors.append("Age must be an integer.")

        if gender not in ("Male", "Female", "Other"):
            errors.append("Invalid gender selection.")

        if not re.match(r"^[6-9]\d{9}$", phone):
            errors.append("Phone must be 10 digits starting with 6, 7, 8, or 9.")

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors.append("Invalid email address format.")

        try:
            plan_id = int(plan_id_str)
            selected_plan = query_db("SELECT id, duration_days FROM membership_plans WHERE id = ?;", (plan_id,), one=True)
            if not selected_plan:
                errors.append("Selected plan does not exist.")
        except ValueError:
            errors.append("Invalid plan selection.")

        try:
            start_dt = date.fromisoformat(start_date_str)
        except ValueError:
            errors.append("Invalid start date format.")

        if recalc_expiry and selected_plan:
            expiry_dt = start_dt + timedelta(days=selected_plan["duration_days"])
        else:
            try:
                expiry_dt = date.fromisoformat(expiry_date_str)
                if expiry_dt < start_dt:
                    errors.append("Expiry date cannot be prior to the start date.")
            except ValueError:
                errors.append("Invalid expiry date format.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template("edit_member.html", active_page="members", member=member, plans=plans)

        db = get_db()
        db.execute(
            """UPDATE members
               SET full_name = ?, age = ?, gender = ?, phone = ?, email = ?, address = ?,
                   plan_id = ?, start_date = ?, expiry_date = ?
               WHERE member_id = ?;""",
            (
                full_name,
                age,
                gender,
                phone,
                email,
                address,
                plan_id,
                start_dt.isoformat(),
                expiry_dt.isoformat(),
                member_id,
            ),
        )
        db.commit()

        flash(f"Profile for {full_name} ({member_id}) updated successfully.", "success")
        return redirect(url_for("member_details", member_id=member_id))

    return render_template("edit_member.html", active_page="members", member=member, plans=plans)


@app.route("/members/<member_id>/renew", methods=["POST"])
@login_required
def member_renew(member_id: str):
    """
    Renew a member's subscription.
    Date logic: Extends from max(today, current_expiry) + plan_duration_days.
    Automatically creates a Paid renewal fee payment in the ledger.
    """
    member = query_db(
        """SELECT m.*, p.plan_name, p.duration_days, p.price
           FROM members m
           JOIN membership_plans p ON m.plan_id = p.id
           WHERE m.member_id = ?;""",
        (member_id,),
        one=True,
    )
    if not member:
        abort(404)

    today = get_today_ist()
    cur_exp = date.fromisoformat(member["expiry_date"])

    # Base date is whichever is further in the future: today or current expiry date
    base_date = max(today, cur_exp)
    new_expiry = base_date + timedelta(days=member["duration_days"])

    db = get_db()
    # 1. Update member's expiry date
    db.execute(
        "UPDATE members SET expiry_date = ? WHERE member_id = ?;",
        (new_expiry.isoformat(), member_id),
    )

    # 2. Record corresponding renewal payment
    row = query_db(
        "SELECT MAX(CAST(SUBSTR(payment_id, 5) AS INTEGER)) AS max_pay FROM payments WHERE payment_id LIKE 'PAY-%';",
        one=True,
    )
    next_pay_num = (row["max_pay"] + 1) if (row and row["max_pay"]) else 5001
    pay_id = f"PAY-{next_pay_num}"

    db.execute(
        """INSERT INTO payments (payment_id, member_id, amount, payment_method, payment_date, status)
           VALUES (?, ?, ?, 'UPI', ?, 'Paid');""",
        (pay_id, member_id, member["price"], today.isoformat()),
    )
    db.commit()

    flash(
        f"Membership for {member['full_name']} renewed successfully! "
        f"New expiry date: {new_expiry.strftime('%d-%m-%Y')}. Fee payment {pay_id} recorded.",
        "success",
    )
    return redirect(url_for("member_details", member_id=member_id))


@app.route("/members/<member_id>/delete", methods=["GET"])
@login_required
def member_delete_confirm(member_id: str):
    """Dedicated deletion confirmation page displaying CASCADE consequences."""
    member = query_db("SELECT * FROM members WHERE member_id = ?;", (member_id,), one=True)
    if not member:
        abort(404)

    return render_template(
        "confirm_delete.html",
        active_page="members",
        item_type="Member Profile",
        item_id=member["member_id"],
        item_name=member["full_name"],
        extra_info=f"Phone: {member['phone']} | Email: {member['email']}",
        cascade_warning=True,
        cancel_url=url_for("member_details", member_id=member_id),
        delete_url=url_for("member_delete_action", member_id=member_id),
    )


@app.route("/members/<member_id>/delete/action", methods=["POST"])
@login_required
def member_delete_action(member_id: str):
    """
    Execute permanent deletion of a member.
    Foreign key ON DELETE CASCADE automatically purges all payments and attendance.
    """
    member = query_db("SELECT full_name FROM members WHERE member_id = ?;", (member_id,), one=True)
    if not member:
        abort(404)

    db = get_db()
    db.execute("DELETE FROM members WHERE member_id = ?;", (member_id,))
    db.commit()

    flash(f"Member {member['full_name']} ({member_id}) and all linked records permanently deleted.", "info")
    return redirect(url_for("members_list"))


# ==============================================================================
# SECTION 8: MEMBERSHIP PLANS & PRICING
# ==============================================================================


@app.route("/plans")
@login_required
def plans_list():
    """Display available membership plans with enrolled member count."""
    plans = query_db(
        """SELECT p.*, COUNT(m.id) AS member_count
           FROM membership_plans p
           LEFT JOIN members m ON p.id = m.plan_id
           GROUP BY p.id
           ORDER BY p.price ASC;"""
    )
    return render_template(
        "membership_plans.html",
        active_page="plans",
        plans=plans,
        editing_plan=None,
        form_data={},
    )


@app.route("/plans/add", methods=["POST"])
@login_required
def plan_add():
    """Create a new membership package tier."""
    plan_name = request.form.get("plan_name", "").strip()
    duration_str = request.form.get("duration_days", "").strip()
    price_str = request.form.get("price", "").strip()
    description = request.form.get("description", "").strip()

    errors = []
    if not plan_name:
        errors.append("Plan name is required.")
    try:
        duration_days = int(duration_str)
        if duration_days <= 0:
            errors.append("Plan duration must be at least 1 day.")
    except ValueError:
        errors.append("Duration must be an integer number of days.")

    try:
        price = float(price_str)
        if price < 0:
            errors.append("Price cannot be negative.")
    except ValueError:
        errors.append("Price must be a valid numeric amount.")

    existing = query_db("SELECT id FROM membership_plans WHERE plan_name = ?;", (plan_name,), one=True)
    if existing:
        errors.append(f"A plan named '{plan_name}' already exists.")

    if errors:
        for err in errors:
            flash(err, "danger")
        plans = query_db(
            """SELECT p.*, COUNT(m.id) AS member_count
               FROM membership_plans p
               LEFT JOIN members m ON p.id = m.plan_id
               GROUP BY p.id ORDER BY p.price ASC;"""
        )
        return render_template(
            "membership_plans.html",
            active_page="plans",
            plans=plans,
            editing_plan=None,
            form_data=request.form,
        )

    db = get_db()
    db.execute(
        "INSERT INTO membership_plans (plan_name, duration_days, price, description) VALUES (?, ?, ?, ?);",
        (plan_name, duration_days, price, description),
    )
    db.commit()

    flash(f"Membership plan '{plan_name}' created successfully.", "success")
    return redirect(url_for("plans_list"))


@app.route("/plans/<int:plan_id>/edit", methods=["GET", "POST"])
@login_required
def plan_edit(plan_id: int):
    """Modify membership package details."""
    plan = query_db("SELECT * FROM membership_plans WHERE id = ?;", (plan_id,), one=True)
    if not plan:
        abort(404)

    if request.method == "POST":
        plan_name = request.form.get("plan_name", "").strip()
        duration_str = request.form.get("duration_days", "").strip()
        price_str = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()

        errors = []
        if not plan_name:
            errors.append("Plan name is required.")
        try:
            duration_days = int(duration_str)
            if duration_days <= 0:
                errors.append("Duration must be greater than zero.")
        except ValueError:
            errors.append("Invalid duration value.")

        try:
            price = float(price_str)
            if price < 0:
                errors.append("Price cannot be negative.")
        except ValueError:
            errors.append("Invalid price value.")

        existing = query_db(
            "SELECT id FROM membership_plans WHERE plan_name = ? AND id != ?;",
            (plan_name, plan_id),
            one=True,
        )
        if existing:
            errors.append("Another plan with this name already exists.")

        if errors:
            for err in errors:
                flash(err, "danger")
        else:
            db = get_db()
            db.execute(
                """UPDATE membership_plans
                   SET plan_name = ?, duration_days = ?, price = ?, description = ?
                   WHERE id = ?;""",
                (plan_name, duration_days, price, description, plan_id),
            )
            db.commit()
            flash(f"Plan '{plan_name}' updated successfully.", "success")
            return redirect(url_for("plans_list"))

    plans = query_db(
        """SELECT p.*, COUNT(m.id) AS member_count
           FROM membership_plans p
           LEFT JOIN members m ON p.id = m.plan_id
           GROUP BY p.id ORDER BY p.price ASC;"""
    )
    return render_template(
        "membership_plans.html",
        active_page="plans",
        plans=plans,
        editing_plan=plan,
        form_data={},
    )


@app.route("/plans/<int:plan_id>/delete", methods=["GET"])
@login_required
def plan_delete_confirm(plan_id: int):
    """Confirm plan deletion. Blocked if any members are currently assigned to the plan."""
    plan = query_db("SELECT * FROM membership_plans WHERE id = ?;", (plan_id,), one=True)
    if not plan:
        abort(404)

    # Check member usage
    usage = query_db("SELECT COUNT(*) AS count FROM members WHERE plan_id = ?;", (plan_id,), one=True)
    if usage and usage["count"] > 0:
        flash(
            f"Cannot delete plan '{plan['plan_name']}' because {usage['count']} active athlete(s) "
            "are currently assigned to it. Please reassign those members before deleting.",
            "danger",
        )
        return redirect(url_for("plans_list"))

    return render_template(
        "confirm_delete.html",
        active_page="plans",
        item_type="Membership Plan",
        item_id=f"Plan #{plan['id']}",
        item_name=plan["plan_name"],
        extra_info=f"Duration: {plan['duration_days']} Days | Fee: ₹{plan['price']:,.2f}",
        cascade_warning=False,
        cancel_url=url_for("plans_list"),
        delete_url=url_for("plan_delete_action", plan_id=plan_id),
    )


@app.route("/plans/<int:plan_id>/delete/action", methods=["POST"])
@login_required
def plan_delete_action(plan_id: int):
    """Execute deletion of an unassigned plan."""
    usage = query_db("SELECT COUNT(*) AS count FROM members WHERE plan_id = ?;", (plan_id,), one=True)
    if usage and usage["count"] > 0:
        flash("Action blocked: Members are actively assigned to this plan.", "danger")
        return redirect(url_for("plans_list"))

    db = get_db()
    db.execute("DELETE FROM membership_plans WHERE id = ?;", (plan_id,))
    db.commit()

    flash("Membership plan deleted successfully.", "info")
    return redirect(url_for("plans_list"))


# ==============================================================================
# SECTION 9: TRAINERS & COACHING STAFF
# ==============================================================================


def generate_next_trainer_id() -> str:
    """Generate sequential trainer ID: TRN-101, TRN-102... from MAX numeric suffix."""
    row = query_db(
        "SELECT MAX(CAST(SUBSTR(trainer_id, 5) AS INTEGER)) AS max_trn FROM trainers WHERE trainer_id LIKE 'TRN-%';",
        one=True,
    )
    next_num = (row["max_trn"] + 1) if (row and row["max_trn"]) else 101
    return f"TRN-{next_num}"


@app.route("/trainers")
@login_required
def trainers_list():
    """Roster of trainers with search and pagination."""
    search_query = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 10
    offset = (page - 1) * per_page

    where_sql = "1=1"
    params: List[Any] = []
    if search_query:
        where_sql = "(full_name LIKE ? OR trainer_id LIKE ? OR specialization LIKE ? OR phone LIKE ?)"
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term, like_term])

    count_row = query_db(f"SELECT COUNT(*) AS total FROM trainers WHERE {where_sql};", tuple(params), one=True)
    total_count = count_row["total"] if count_row else 0
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    trainers = query_db(
        f"SELECT * FROM trainers WHERE {where_sql} ORDER BY id ASC LIMIT ? OFFSET ?;",
        tuple(params + [per_page, offset]),
    )

    return render_template(
        "trainers.html",
        active_page="trainers",
        trainers=trainers,
        total_count=total_count,
        total_pages=total_pages,
        current_page=page,
        search_query=search_query,
        editing_trainer=None,
        form_data={},
    )


@app.route("/trainers/add", methods=["POST"])
@login_required
def trainer_add():
    """Register a new gym trainer or coach."""
    full_name = request.form.get("full_name", "").strip()
    specialization = request.form.get("specialization", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    experience_str = request.form.get("experience", "").strip()
    salary_str = request.form.get("salary", "").strip()
    availability = request.form.get("availability", "").strip()

    errors = []
    if not full_name:
        errors.append("Coach name is required.")
    if not specialization:
        errors.append("Specialization discipline is required.")
    if not re.match(r"^[6-9]\d{9}$", phone):
        errors.append("Phone must be 10 digits starting with 6, 7, 8, or 9.")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        errors.append("Invalid email format.")

    try:
        experience = int(experience_str)
        if experience < 0 or experience > 50:
            errors.append("Experience must be between 0 and 50 years.")
    except ValueError:
        errors.append("Experience must be a whole number.")

    try:
        salary = float(salary_str)
        if salary < 0:
            errors.append("Salary cannot be negative.")
    except ValueError:
        errors.append("Salary must be a valid numeric amount.")

    if availability not in ("Full-time", "Part-time"):
        errors.append("Availability must be Full-time or Part-time.")

    if errors:
        for err in errors:
            flash(err, "danger")
        trainers = query_db("SELECT * FROM trainers ORDER BY id ASC LIMIT 10;")
        return render_template(
            "trainers.html",
            active_page="trainers",
            trainers=trainers,
            total_count=len(trainers),
            total_pages=1,
            current_page=1,
            search_query="",
            editing_trainer=None,
            form_data=request.form,
        )

    trainer_id = generate_next_trainer_id()
    db = get_db()
    db.execute(
        """INSERT INTO trainers (trainer_id, full_name, specialization, phone, email, experience, salary, availability)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
        (trainer_id, full_name, specialization, phone, email, experience, salary, availability),
    )
    db.commit()

    flash(f"Trainer {full_name} ({trainer_id}) added successfully.", "success")
    return redirect(url_for("trainers_list"))


@app.route("/trainers/<trainer_id>/edit", methods=["GET", "POST"])
@login_required
def trainer_edit(trainer_id: str):
    """Edit trainer details."""
    trainer = query_db("SELECT * FROM trainers WHERE trainer_id = ?;", (trainer_id,), one=True)
    if not trainer:
        abort(404)

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        specialization = request.form.get("specialization", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        experience_str = request.form.get("experience", "").strip()
        salary_str = request.form.get("salary", "").strip()
        availability = request.form.get("availability", "").strip()

        errors = []
        if not full_name:
            errors.append("Name is required.")
        if not specialization:
            errors.append("Specialization is required.")
        if not re.match(r"^[6-9]\d{9}$", phone):
            errors.append("Phone must be 10 digits starting with 6, 7, 8, or 9.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors.append("Invalid email.")

        try:
            experience = int(experience_str)
            if experience < 0 or experience > 50:
                errors.append("Experience must be 0-50.")
        except ValueError:
            errors.append("Invalid experience value.")

        try:
            salary = float(salary_str)
            if salary < 0:
                errors.append("Salary cannot be negative.")
        except ValueError:
            errors.append("Invalid salary.")

        if availability not in ("Full-time", "Part-time"):
            errors.append("Invalid availability.")

        if errors:
            for err in errors:
                flash(err, "danger")
        else:
            db = get_db()
            db.execute(
                """UPDATE trainers
                   SET full_name = ?, specialization = ?, phone = ?, email = ?,
                       experience = ?, salary = ?, availability = ?
                   WHERE trainer_id = ?;""",
                (full_name, specialization, phone, email, experience, salary, availability, trainer_id),
            )
            db.commit()
            flash(f"Trainer {full_name} ({trainer_id}) updated successfully.", "success")
            return redirect(url_for("trainers_list"))

    trainers = query_db("SELECT * FROM trainers ORDER BY id ASC LIMIT 10;")
    return render_template(
        "trainers.html",
        active_page="trainers",
        trainers=trainers,
        total_count=len(trainers),
        total_pages=1,
        current_page=1,
        search_query="",
        editing_trainer=trainer,
        form_data={},
    )


@app.route("/trainers/<trainer_id>/delete", methods=["GET"])
@login_required
def trainer_delete_confirm(trainer_id: str):
    """Confirm trainer deletion."""
    trainer = query_db("SELECT * FROM trainers WHERE trainer_id = ?;", (trainer_id,), one=True)
    if not trainer:
        abort(404)

    return render_template(
        "confirm_delete.html",
        active_page="trainers",
        item_type="Trainer Profile",
        item_id=trainer["trainer_id"],
        item_name=trainer["full_name"],
        extra_info=f"Specialization: {trainer['specialization']} | Salary: ₹{trainer['salary']:,.2f}",
        cascade_warning=False,
        cancel_url=url_for("trainers_list"),
        delete_url=url_for("trainer_delete_action", trainer_id=trainer_id),
    )


@app.route("/trainers/<trainer_id>/delete/action", methods=["POST"])
@login_required
def trainer_delete_action(trainer_id: str):
    """Execute trainer record deletion."""
    trainer = query_db("SELECT full_name FROM trainers WHERE trainer_id = ?;", (trainer_id,), one=True)
    if not trainer:
        abort(404)

    db = get_db()
    db.execute("DELETE FROM trainers WHERE trainer_id = ?;", (trainer_id,))
    db.commit()

    flash(f"Trainer {trainer['full_name']} ({trainer_id}) deleted successfully.", "info")
    return redirect(url_for("trainers_list"))


# ==============================================================================
# SECTION 10: PAYMENTS, TWO-STEP BILLING & RECEIPTS
# ==============================================================================


def generate_next_payment_id() -> str:
    """Generate sequential receipt ID: PAY-5001, PAY-5002... from MAX numeric suffix."""
    row = query_db(
        "SELECT MAX(CAST(SUBSTR(payment_id, 5) AS INTEGER)) AS max_pay FROM payments WHERE payment_id LIKE 'PAY-%';",
        one=True,
    )
    next_num = (row["max_pay"] + 1) if (row and row["max_pay"]) else 5001
    return f"PAY-{next_num}"


@app.route("/payments")
@login_required
def payments_list():
    """
    Financial ledger listing payment transactions.
    Supports filtering by payment method, status, date range, and text search.
    Computes total collected amount for the active filter set.
    """
    search_query = request.args.get("q", "").strip()
    selected_method = request.args.get("method", "").strip()
    selected_status = request.args.get("status", "").strip()
    selected_start_date = request.args.get("start_date", "").strip()
    selected_end_date = request.args.get("end_date", "").strip()

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 10
    offset = (page - 1) * per_page

    where_clauses = ["1=1"]
    params: List[Any] = []

    if search_query:
        where_clauses.append("(p.payment_id LIKE ? OR m.full_name LIKE ? OR m.member_id LIKE ?)")
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term])

    if selected_method:
        where_clauses.append("p.payment_method = ?")
        params.append(selected_method)

    if selected_status:
        where_clauses.append("p.status = ?")
        params.append(selected_status)

    if selected_start_date:
        where_clauses.append("p.payment_date >= ?")
        params.append(selected_start_date)

    if selected_end_date:
        where_clauses.append("p.payment_date <= ?")
        params.append(selected_end_date)

    where_sql = " AND ".join(where_clauses)

    # Total revenue for active filter set
    total_rev_row = query_db(
        f"""SELECT COALESCE(SUM(p.amount), 0.0) AS total_sum, COUNT(*) AS count
           FROM payments p
           JOIN members m ON p.member_id = m.member_id
           WHERE {where_sql};""",
        tuple(params),
        one=True,
    )
    total_filtered_amount = total_rev_row["total_sum"] if total_rev_row else 0.0
    total_count = total_rev_row["count"] if total_rev_row else 0
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    payments = query_db(
        f"""SELECT p.id, p.payment_id, p.member_id, p.amount, p.payment_method,
                   p.payment_date, p.status, m.full_name
            FROM payments p
            JOIN members m ON p.member_id = m.member_id
            WHERE {where_sql}
            ORDER BY p.payment_date DESC, p.id DESC
            LIMIT ? OFFSET ?;""",
        tuple(params + [per_page, offset]),
    )

    all_members = query_db(
        """SELECT m.member_id, m.full_name, pl.plan_name, pl.price AS plan_price
           FROM members m
           JOIN membership_plans pl ON m.plan_id = pl.id
           ORDER BY m.full_name ASC;"""
    )

    return render_template(
        "payments.html",
        active_page="payments",
        payments=payments,
        all_members=all_members,
        selected_member=None,
        total_filtered_amount=total_filtered_amount,
        total_count=total_count,
        total_pages=total_pages,
        current_page=page,
        search_query=search_query,
        selected_method=selected_method,
        selected_status=selected_status,
        selected_start_date=selected_start_date,
        selected_end_date=selected_end_date,
    )


@app.route("/payments/record", methods=["GET", "POST"])
@login_required
def payments_record():
    """
    Two-step server-side payment collection flow:
    Step 1 (GET): Pick member -> pre-fills plan fee and membership details.
    Step 2 (POST): Confirm details -> writes to DB and redirects to official receipt.
    """
    member_id_arg = request.args.get("member_id", "").strip()

    if request.method == "POST":
        member_id = request.form.get("member_id", "").strip()
        amount_str = request.form.get("amount", "").strip()
        payment_method = request.form.get("payment_method", "").strip()
        status = request.form.get("status", "").strip()
        payment_date = request.form.get("payment_date", "").strip()

        errors = []
        member = query_db("SELECT full_name FROM members WHERE member_id = ?;", (member_id,), one=True)
        if not member:
            errors.append("Invalid member selected.")

        try:
            amount = float(amount_str)
            if amount < 0:
                errors.append("Payment amount cannot be negative.")
        except ValueError:
            errors.append("Invalid amount.")

        if payment_method not in ("Cash", "UPI", "Card"):
            errors.append("Invalid payment method.")

        if status not in ("Paid", "Pending"):
            errors.append("Invalid status.")

        try:
            date.fromisoformat(payment_date)
        except ValueError:
            errors.append("Invalid payment date.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return redirect(url_for("payments_record", member_id=member_id))

        payment_id = generate_next_payment_id()
        db = get_db()
        db.execute(
            """INSERT INTO payments (payment_id, member_id, amount, payment_method, payment_date, status)
               VALUES (?, ?, ?, ?, ?, ?);""",
            (payment_id, member_id, amount, payment_method, payment_date, status),
        )
        db.commit()

        flash(f"Payment {payment_id} of ₹{amount:,.2f} recorded for {member['full_name']}!", "success")
        return redirect(url_for("payment_receipt", payment_id=payment_id))

    # GET Step 1 or Step 2
    selected_member = None
    if member_id_arg:
        selected_member = query_db(
            """SELECT m.member_id, m.full_name, pl.plan_name, pl.price AS plan_price, pl.duration_days
               FROM members m
               JOIN membership_plans pl ON m.plan_id = pl.id
               WHERE m.member_id = ?;""",
            (member_id_arg,),
            one=True,
        )

    all_members = query_db(
        """SELECT m.member_id, m.full_name, pl.plan_name, pl.price AS plan_price
           FROM members m
           JOIN membership_plans pl ON m.plan_id = pl.id
           ORDER BY m.full_name ASC;"""
    )

    # Render payments ledger with step 2 form opened
    payments = query_db(
        """SELECT p.id, p.payment_id, p.member_id, p.amount, p.payment_method,
                  p.payment_date, p.status, m.full_name
           FROM payments p
           JOIN members m ON p.member_id = m.member_id
           ORDER BY p.payment_date DESC, p.id DESC
           LIMIT 10;"""
    )

    return render_template(
        "payments.html",
        active_page="payments",
        payments=payments,
        all_members=all_members,
        selected_member=selected_member,
        total_filtered_amount=0.0,
        total_count=len(payments),
        total_pages=1,
        current_page=1,
        search_query="",
        selected_method="",
        selected_status="",
        selected_start_date="",
        selected_end_date="",
    )


@app.route("/payments/receipt/<payment_id>")
@login_required
def payment_receipt(payment_id: str):
    """
    Render formal, print-ready payment receipt.
    Includes gym metadata, member contact, plan breakdown, and thank-you notice.
    """
    payment = query_db(
        """SELECT p.payment_id, p.amount, p.payment_method, p.payment_date, p.status,
                  m.member_id, m.full_name, m.phone, m.email,
                  pl.plan_name, pl.duration_days
           FROM payments p
           JOIN members m ON p.member_id = m.member_id
           JOIN membership_plans pl ON m.plan_id = pl.id
           WHERE p.payment_id = ?;""",
        (payment_id,),
        one=True,
    )
    if not payment:
        abort(404)

    return render_template(
        "receipt.html",
        active_page="payments",
        payment=payment,
        gym_tagline=get_gym_setting("gym_tagline", "Unleash Your Strength"),
        gym_phone=get_gym_setting("gym_phone", "+91 98220 12345"),
        gym_email=get_gym_setting("gym_email", "contact@ironcoregym.in"),
        gym_address=get_gym_setting("gym_address", "Plot 42, FC Road, Shivajinagar, Pune - 411005"),
    )


# ==============================================================================
# SECTION 11: ATTENDANCE TRACKING & PURE-CSS TRENDS
# ==============================================================================


@app.route("/attendance")
@login_required
def attendance_view():
    """
    Workout attendance log.
    Displays check-ins for the selected date and renders a pure-CSS 7-day trend chart.
    """
    selected_date = request.args.get("date", "").strip()
    search_query = request.args.get("q", "").strip()

    today = get_today_ist()
    if not selected_date:
        selected_date = today.isoformat()

    # Query attendance records for the selected date
    where_sql = "a.attendance_date = ?"
    params: List[Any] = [selected_date]

    if search_query:
        where_sql += " AND (m.full_name LIKE ? OR m.member_id LIKE ?)"
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term])

    attendance_records = query_db(
        f"""SELECT a.id, a.member_id, a.attendance_date, a.check_in_time,
                   m.full_name, m.phone, m.expiry_date, p.plan_name
            FROM attendance a
            JOIN members m ON a.member_id = m.member_id
            JOIN membership_plans p ON m.plan_id = p.id
            WHERE {where_sql}
            ORDER BY a.check_in_time DESC;""",
        tuple(params),
    )

    # Calculate 7-day attendance trend data for pure-CSS bar chart
    last_7_days = []
    max_count = 1
    counts = []

    for i in range(6, -1, -1):
        dt = today - timedelta(days=i)
        dt_iso = dt.isoformat()
        row = query_db(
            "SELECT COUNT(*) AS c FROM attendance WHERE attendance_date = ?;",
            (dt_iso,),
            one=True,
        )
        c = row["c"] if row else 0
        counts.append(c)
        last_7_days.append({
            "iso_date": dt_iso,
            "display_date": dt.strftime("%d %b"),
            "count": c,
        })

    max_count = max(max(counts), 1)
    for day in last_7_days:
        day["pct"] = int((day["count"] / max_count) * 100)

    # All members list for mark-present dropdown
    all_members = query_db(
        "SELECT member_id, full_name, expiry_date FROM members ORDER BY full_name ASC;"
    )

    return render_template(
        "attendance.html",
        active_page="attendance",
        selected_date=selected_date,
        search_query=search_query,
        attendance_records=attendance_records,
        total_today_count=len(attendance_records),
        last_7_days=last_7_days,
        all_members=all_members,
    )


@app.route("/attendance/mark", methods=["POST"])
@login_required
def attendance_mark():
    """
    Mark athlete present for training session.
    Enforces UNIQUE(member_id, attendance_date) with a user-friendly flash pre-check.
    Warns and blocks expired members unless 'Allow Expired Member' is checked.
    """
    member_id = request.form.get("member_id", "").strip()
    allow_expired = request.form.get("allow_expired") == "1"
    att_date = request.form.get("attendance_date", "").strip() or get_today_ist().isoformat()

    member = query_db("SELECT full_name, expiry_date FROM members WHERE member_id = ?;", (member_id,), one=True)
    if not member:
        flash("Selected member does not exist in the database.", "danger")
        return redirect(url_for("attendance_view", date=att_date))

    today_iso = get_today_ist().isoformat()
    # Expired membership check
    if member["expiry_date"] < today_iso and not allow_expired:
        flash(
            f"Access Denied: Membership for {member['full_name']} ({member_id}) expired on "
            f"{date.fromisoformat(member['expiry_date']).strftime('%d-%m-%Y')}. "
            "To override, tick 'Allow Expired Member Check-in' or renew their plan.",
            "warning",
        )
        return redirect(url_for("attendance_view", date=att_date))

    # Duplicate check for the specified date
    existing = query_db(
        "SELECT id, check_in_time FROM attendance WHERE member_id = ? AND attendance_date = ?;",
        (member_id, att_date),
        one=True,
    )
    if existing:
        flash(
            f"{member['full_name']} ({member_id}) is already checked in for {date.fromisoformat(att_date).strftime('%d-%m-%Y')} "
            f"(Timestamp: {existing['check_in_time']}).",
            "info",
        )
        return redirect(url_for("attendance_view", date=att_date))

    checkin_time = get_now_ist().strftime("%H:%M:%S")
    db = get_db()
    db.execute(
        "INSERT INTO attendance (member_id, attendance_date, check_in_time) VALUES (?, ?, ?);",
        (member_id, att_date, checkin_time),
    )
    db.commit()

    flash(f"Check-in confirmed for {member['full_name']} at {checkin_time} (IST)!", "success")
    return redirect(url_for("attendance_view", date=att_date))


# ==============================================================================
# SECTION 12: OPERATIONAL AUDIT REPORTS & IN-MEMORY CSV EXPORTS
# ==============================================================================


@app.route("/reports")
@login_required
def reports_view():
    """
    Facility operational reports dashboard.
    Summarizes membership tiers, 6-month revenue trends, attendance, and coach payroll.
    """
    today = get_today_ist()
    today_iso = today.isoformat()
    seven_days_later_iso = (today + timedelta(days=7)).isoformat()

    filter_plan = request.args.get("plan", "").strip()
    filter_status = request.args.get("status", "").strip()
    filter_start_date = request.args.get("start_date", "").strip()
    filter_end_date = request.args.get("end_date", "").strip()

    # 1. Membership summary
    tot_m = query_db("SELECT COUNT(*) AS c FROM members;", one=True)["c"]
    act_m = query_db("SELECT COUNT(*) AS c FROM members WHERE expiry_date >= ?;", (today_iso,), one=True)["c"]
    exp_m = query_db("SELECT COUNT(*) AS c FROM members WHERE expiry_date < ?;", (today_iso,), one=True)["c"]
    soon_m = query_db(
        "SELECT COUNT(*) AS c FROM members WHERE expiry_date >= ? AND expiry_date <= ?;",
        (today_iso, seven_days_later_iso),
        one=True,
    )["c"]

    member_summary = {
        "total": tot_m,
        "active": act_m,
        "active_pct": int((act_m / tot_m * 100)) if tot_m > 0 else 0,
        "expired": exp_m,
        "expiring_soon": soon_m,
    }

    # 2. Revenue collections by month (last 6 months)
    revenue_by_month_rows = query_db(
        """SELECT SUBSTR(payment_date, 1, 7) AS month_str,
                  COUNT(*) AS tx_count,
                  COALESCE(SUM(amount), 0.0) AS total_amount
           FROM payments
           WHERE status = 'Paid'
           GROUP BY SUBSTR(payment_date, 1, 7)
           ORDER BY month_str DESC
           LIMIT 6;"""
    )
    revenue_by_month = []
    for r in revenue_by_month_rows:
        try:
            m_dt = datetime.strptime(r["month_str"], "%Y-%m")
            label = m_dt.strftime("%B %Y")
        except Exception:
            label = r["month_str"]
        revenue_by_month.append({
            "month_label": label,
            "tx_count": r["tx_count"],
            "total_amount": r["total_amount"],
        })

    # 3. Revenue by plan tier
    revenue_by_plan = query_db(
        """SELECT pl.plan_name,
                  COUNT(DISTINCT m.id) AS member_count,
                  COALESCE(SUM(p.amount), 0.0) AS total_revenue
           FROM membership_plans pl
           LEFT JOIN members m ON pl.id = m.plan_id
           LEFT JOIN payments p ON m.member_id = p.member_id AND p.status = 'Paid'
           GROUP BY pl.id
           ORDER BY total_revenue DESC;"""
    )

    # 4. Trainer staff payroll
    trainers = query_db("SELECT * FROM trainers ORDER BY salary DESC;")
    total_payroll = sum(t["salary"] for t in trainers)

    plans = query_db("SELECT id, plan_name FROM membership_plans ORDER BY price ASC;")

    return render_template(
        "reports.html",
        active_page="reports",
        member_summary=member_summary,
        revenue_by_month=revenue_by_month,
        revenue_by_plan=revenue_by_plan,
        trainers=trainers,
        total_payroll=total_payroll,
        plans=plans,
        filter_plan=filter_plan,
        filter_status=filter_status,
        filter_start_date=filter_start_date,
        filter_end_date=filter_end_date,
    )


@app.route("/reports/export/members")
@login_required
def export_members_csv():
    """
    Stream in-memory CSV export of members database honoring active filters.
    Zero filesystem writes: Uses io.StringIO and csv.writer.
    """
    search_query = request.args.get("q", "").strip()
    selected_plan = request.args.get("plan", "").strip()
    selected_status = request.args.get("status", "").strip()

    today = get_today_ist()
    today_iso = today.isoformat()

    where_clauses = ["1=1"]
    params: List[Any] = []

    if search_query:
        where_clauses.append("(m.full_name LIKE ? OR m.member_id LIKE ? OR m.phone LIKE ? OR m.email LIKE ?)")
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term, like_term])

    if selected_plan:
        where_clauses.append("m.plan_id = ?")
        params.append(selected_plan)

    if selected_status == "active":
        where_clauses.append("m.expiry_date >= ?")
        params.append(today_iso)
    elif selected_status == "expired":
        where_clauses.append("m.expiry_date < ?")
        params.append(today_iso)

    where_sql = " AND ".join(where_clauses)

    rows = query_db(
        f"""SELECT m.member_id, m.full_name, m.age, m.gender, m.phone, m.email, m.address,
                   m.registration_date, m.start_date, m.expiry_date, p.plan_name
            FROM members m
            JOIN membership_plans p ON m.plan_id = p.id
            WHERE {where_sql}
            ORDER BY m.id ASC;""",
        tuple(params),
    )

    si = io.StringIO()
    cw = csv.writer(si)
    # Header
    cw.writerow([
        "Member ID", "Full Name", "Age", "Gender", "Phone", "Email",
        "Residential Address", "Registration Date", "Plan Name", "Start Date", "Expiry Date", "Status"
    ])

    for r in rows:
        status_label = "Active" if r["expiry_date"] >= today_iso else "Expired"
        cw.writerow([
            r["member_id"], r["full_name"], r["age"], r["gender"], r["phone"], r["email"],
            r["address"], r["registration_date"], r["plan_name"], r["start_date"], r["expiry_date"], status_label
        ])

    filename = f"gym_members_{today.strftime('%Y%m%d')}.csv"
    output = si.getvalue()
    si.close()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/reports/export/payments")
@login_required
def export_payments_csv():
    """Stream in-memory CSV export of payments ledger with date stamped filename."""
    selected_method = request.args.get("method", "").strip()
    selected_status = request.args.get("status", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    where_clauses = ["1=1"]
    params: List[Any] = []

    if selected_method:
        where_clauses.append("p.payment_method = ?")
        params.append(selected_method)
    if selected_status:
        where_clauses.append("p.status = ?")
        params.append(selected_status)
    if start_date:
        where_clauses.append("p.payment_date >= ?")
        params.append(start_date)
    if end_date:
        where_clauses.append("p.payment_date <= ?")
        params.append(end_date)

    where_sql = " AND ".join(where_clauses)

    rows = query_db(
        f"""SELECT p.payment_id, p.member_id, m.full_name, p.amount,
                   p.payment_method, p.payment_date, p.status, pl.plan_name
            FROM payments p
            JOIN members m ON p.member_id = m.member_id
            JOIN membership_plans pl ON m.plan_id = pl.id
            WHERE {where_sql}
            ORDER BY p.payment_date DESC, p.id DESC;""",
        tuple(params),
    )

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow([
        "Payment ID", "Member ID", "Member Name", "Plan Name",
        "Amount (INR)", "Payment Method", "Payment Date", "Status"
    ])

    for r in rows:
        cw.writerow([
            r["payment_id"], r["member_id"], r["full_name"], r["plan_name"],
            f"{r['amount']:.2f}", r["payment_method"], r["payment_date"], r["status"]
        ])

    today_str = get_today_ist().strftime("%Y%m%d")
    filename = f"gym_payments_{today_str}.csv"
    output = si.getvalue()
    si.close()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/reports/export/attendance")
@login_required
def export_attendance_csv():
    """Stream in-memory CSV export of workout check-ins."""
    date_arg = request.args.get("date", "").strip()

    where_sql = "1=1"
    params: List[Any] = []
    if date_arg:
        where_sql = "a.attendance_date = ?"
        params.append(date_arg)

    rows = query_db(
        f"""SELECT a.attendance_date, a.check_in_time, a.member_id,
                   m.full_name, m.phone, pl.plan_name
            FROM attendance a
            JOIN members m ON a.member_id = m.member_id
            JOIN membership_plans pl ON m.plan_id = pl.id
            WHERE {where_sql}
            ORDER BY a.attendance_date DESC, a.check_in_time DESC;""",
        tuple(params),
    )

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow([
        "Attendance Date", "Check-in Time (IST)", "Member ID", "Member Name", "Phone", "Plan Name"
    ])

    for r in rows:
        cw.writerow([
            r["attendance_date"], r["check_in_time"], r["member_id"],
            r["full_name"], r["phone"], r["plan_name"]
        ])

    today_str = get_today_ist().strftime("%Y%m%d")
    filename = f"gym_attendance_{today_str}.csv"
    output = si.getvalue()
    si.close()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ==============================================================================
# SECTION 13: SYSTEM SETTINGS & CREDENTIALS
# ==============================================================================


@app.route("/settings")
@login_required
def settings_view():
    """Administrative configuration console for password and branding."""
    settings_rows = query_db("SELECT key, value FROM settings;")
    settings_dict = {r["key"]: r["value"] for r in settings_rows}

    return render_template(
        "settings.html",
        active_page="settings",
        settings=settings_dict,
    )


@app.route("/settings/gym-info", methods=["POST"])
@login_required
def settings_gym_info():
    """Update gym brand name and physical address metadata."""
    gym_name = request.form.get("gym_name", "").strip()
    gym_tagline = request.form.get("gym_tagline", "").strip()
    gym_phone = request.form.get("gym_phone", "").strip()
    gym_email = request.form.get("gym_email", "").strip()
    gym_address = request.form.get("gym_address", "").strip()

    if not gym_name:
        flash("Facility name cannot be left empty.", "danger")
        return redirect(url_for("settings_view"))

    db = get_db()
    items = [
        ("gym_name", gym_name),
        ("gym_tagline", gym_tagline),
        ("gym_phone", gym_phone),
        ("gym_email", gym_email),
        ("gym_address", gym_address),
    ]
    for key, val in items:
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?;",
            (key, val, val),
        )
    db.commit()

    flash("Gym branding and facility contact information saved successfully.", "success")
    return redirect(url_for("settings_view"))


@app.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    """
    Change administrator authentication password.
    Enforces current password verification, 8+ characters minimum, and confirmation match.
    """
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    user = query_db("SELECT * FROM users WHERE id = ?;", (session.get("user_id"),), one=True)
    if not user or not check_password_hash(user["password_hash"], current_password):
        flash("Current password verification failed. Please check your existing password.", "danger")
        return redirect(url_for("settings_view"))

    if len(new_password) < 8:
        flash("New password must contain at least 8 characters for security compliance.", "danger")
        return redirect(url_for("settings_view"))

    if new_password != confirm_password:
        flash("New password and confirmation password do not match.", "danger")
        return redirect(url_for("settings_view"))

    new_hash = generate_password_hash(new_password)
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?;", (new_hash, user["id"]))
    db.commit()

    flash("Administrator password updated successfully. Please use your new password next time.", "success")
    return redirect(url_for("settings_view"))


# ==============================================================================
# SECTION 14: CUSTOM ERROR HANDLERS (ZERO STACK TRACES)
# ==============================================================================


@app.errorhandler(400)
def handle_bad_request(error):
    """Handle 400 Bad Request errors (such as CSRF rejections)."""
    desc = getattr(error, "description", "The request was invalid or incomplete.")
    return render_template(
        "404.html",
        active_page="",
        page_title="400 - Bad Request",
        error_title="Request Rejected (HTTP 400)",
        error_desc=str(desc),
    ), 400


@app.errorhandler(404)
def handle_not_found(error):
    """Handle 404 Not Found error matching dark theme."""
    return render_template("404.html", active_page=""), 404


@app.errorhandler(500)
def handle_server_error(error):
    """Handle 500 Internal Server Error cleanly without exposing stack traces."""
    return render_template(
        "404.html",
        active_page="",
        page_title="500 - Server Error",
        error_title="Internal System Error (HTTP 500)",
        error_desc="An internal server error occurred. Please contact the system administrator.",
    ), 500


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    # Local development server running on port 5000
    app.run(host="127.0.0.1", port=5000, debug=True)
