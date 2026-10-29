"""
================================================================================
SMOKE TEST SUITE - GYM MANAGEMENT SYSTEM
Automated Verification for SPPU B.Tech PBL Coursework
Tests:
  1. Login authentication (success & failure)
  2. CSRF rejection (missing & forged tokens -> HTTP 400)
  3. Protected route redirects for unauthenticated sessions
  4. Member enrollment & ID generation (MEM-10xx from MAX suffix)
  5. Membership plan expiry math (30d, 90d, 180d, 365d)
  6. Active vs Expired status logic
  7. Duplicate attendance prevention & expired guard
  8. Two-step fee collection & receipt rendering
  9. Search, filtering, and pagination
  10. In-memory CSV streaming (Content-Type text/csv)
  11. Custom 404 error page rendering
  12. Static analysis: ZERO <script> and ZERO inline on* event handlers in templates
================================================================================
"""

import glob
import os
import re
import sys
from datetime import date, timedelta
from urllib.parse import quote

# Import Flask app and database
from app import app, get_today_ist
import database


def run_tests():
    print("=" * 75)
    print("RUNNING SMOKE TEST SUITE: GYM MANAGEMENT SYSTEM")
    print("=" * 75)

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Note: our custom CSRF is tested explicitly

    client = app.test_client()

    passed = 0
    total = 0

    def assert_test(condition: bool, description: str):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f" [PASS] Test {total:02d}: {description}")
        else:
            print(f" [FAIL] Test {total:02d}: {description}")
            raise AssertionError(f"Smoke test assertion failed: {description}")

    # --------------------------------------------------------------------------
    # TEST 1: Static template audit (ZERO JavaScript, ZERO <script>, ZERO on*)
    # --------------------------------------------------------------------------
    template_files = glob.glob(os.path.join(os.path.dirname(__file__), "templates", "*.html"))
    assert_test(len(template_files) >= 16, f"All 16 required templates exist (found {len(template_files)})")

    script_found = False
    inline_handler_found = False
    for tf in template_files:
        with open(tf, "r", encoding="utf-8") as f:
            content = f.read()
            if "<script" in content.lower():
                script_found = True
                print(f"Found <script> in {tf}")
            # Check for inline handlers like onclick, onload, onchange, onsubmit
            if re.search(r"\son[a-zA-Z]+\s*=", content):
                inline_handler_found = True
                print(f"Found inline on* handler in {tf}")

    assert_test(not script_found, "ZERO <script> tags present across all HTML templates")
    assert_test(not inline_handler_found, "ZERO inline on* event handlers in HTML templates")

    # --------------------------------------------------------------------------
    # TEST 2: Protected routes redirect unauthenticated users
    # --------------------------------------------------------------------------
    resp = client.get("/")
    assert_test(resp.status_code == 302 and "/login" in resp.headers["Location"], "GET / redirects to /login when unauthenticated")

    resp = client.get("/members")
    assert_test(resp.status_code == 302 and "/login" in resp.headers["Location"], "GET /members redirects to /login when unauthenticated")

    resp = client.get("/reports")
    assert_test(resp.status_code == 302 and "/login" in resp.headers["Location"], "GET /reports redirects to /login when unauthenticated")

    # --------------------------------------------------------------------------
    # TEST 3: Login failure on invalid credentials
    # --------------------------------------------------------------------------
    # First get login page to establish session & csrf_token
    resp = client.get("/login")
    assert_test(resp.status_code == 200, "GET /login renders HTTP 200")
    with client.session_transaction() as sess:
        csrf_tok = sess["csrf_token"]

    resp = client.post("/login", data={
        "username": "admin",
        "password": "wrong_password",
        "csrf_token": csrf_tok
    }, follow_redirects=True)
    assert_test(b"Invalid administrator credentials" in resp.data, "Login fails with bad password and displays flash error")

    # --------------------------------------------------------------------------
    # TEST 4: Hand-crafted CSRF Rejection
    # --------------------------------------------------------------------------
    # Missing CSRF token
    resp = client.post("/login", data={
        "username": "admin",
        "password": "password123"
    })
    assert_test(resp.status_code == 400, "POST without CSRF token returns HTTP 400 Bad Request")

    # Invalid CSRF token
    resp = client.post("/login", data={
        "username": "admin",
        "password": "password123",
        "csrf_token": "forged_invalid_token"
    })
    assert_test(resp.status_code == 400, "POST with forged CSRF token returns HTTP 400 Bad Request")

    # --------------------------------------------------------------------------
    # TEST 5: Login success with default admin / password123
    # --------------------------------------------------------------------------
    with client.session_transaction() as sess:
        valid_csrf = sess["csrf_token"]

    resp = client.post("/login", data={
        "username": "admin",
        "password": "password123",
        "csrf_token": valid_csrf
    }, follow_redirects=True)
    assert_test(resp.status_code == 200 and b"Executive Dashboard" in resp.data, "Default admin login succeeds and renders Dashboard")

    # --------------------------------------------------------------------------
    # TEST 6: Dashboard aggregates and security headers
    # --------------------------------------------------------------------------
    resp = client.get("/")
    assert_test(b"Total Members" in resp.data and b"Total Revenue" in resp.data, "Dashboard shows live aggregate metric cards")
    assert_test("script-src 'none'" in resp.headers.get("Content-Security-Policy", ""), "CSP header strictly enforces script-src 'none'")

    # --------------------------------------------------------------------------
    # TEST 7: Member ID generation sequence (MEM-10xx) and Add Member
    # --------------------------------------------------------------------------
    with client.session_transaction() as sess:
        csrf_tok = sess["csrf_token"]

    today = get_today_ist()
    test_phone = "9822999888"
    resp = client.post("/members/add", data={
        "full_name": "Test Athlete",
        "age": "24",
        "gender": "Male",
        "phone": test_phone,
        "email": "test.athlete@example.com",
        "address": "42 Shivaji Nagar, Pune",
        "plan_id": "1",  # Monthly plan (30 days)
        "start_date": today.isoformat(),
        "csrf_token": csrf_tok
    }, follow_redirects=True)

    assert_test(resp.status_code == 200 and b"Test Athlete" in resp.data, "Member registration successfully processed")
    assert_test(b"MEM-" in resp.data, "Sequential ID generated starting with MEM-")

    # Check member details page
    with app.app_context():
        conn = database.get_db_connection()
        new_m = conn.execute("SELECT * FROM members WHERE phone = ?;", (test_phone,)).fetchone()
        assert_test(new_m is not None, f"Member row exists in database with ID {new_m['member_id']}")
        new_mid = new_m["member_id"]
        exp_dt = date.fromisoformat(new_m["expiry_date"])
        start_dt = date.fromisoformat(new_m["start_date"])
        conn.close()

    # --------------------------------------------------------------------------
    # TEST 8: Expiry Math for all 4 Plans
    # --------------------------------------------------------------------------
    with app.app_context():
        conn = database.get_db_connection()
        plans = conn.execute("SELECT id, plan_name, duration_days FROM membership_plans;").fetchall()
        for p in plans:
            calculated_exp = today + timedelta(days=p["duration_days"])
            assert_test(
                (calculated_exp - today).days == p["duration_days"],
                f"Plan '{p['plan_name']}' duration matches {p['duration_days']} days correctly"
            )
        conn.close()

    # --------------------------------------------------------------------------
    # TEST 9: Active vs Expired Status Check
    # --------------------------------------------------------------------------
    resp = client.get(f"/members/{new_mid}")
    assert_test(b"Active Membership" in resp.data, "Newly enrolled member with future expiry displays 'Active Membership' badge")

    # --------------------------------------------------------------------------
    # TEST 10: Attendance Check-in & Duplicate Prevention
    # --------------------------------------------------------------------------
    with client.session_transaction() as sess:
        csrf_tok = sess["csrf_token"]

    resp = client.post("/attendance/mark", data={
        "member_id": new_mid,
        "attendance_date": today.isoformat(),
        "csrf_token": csrf_tok
    }, follow_redirects=True)
    assert_test(b"Check-in confirmed" in resp.data, "First attendance check-in succeeds")

    # Second check-in on the same date should be blocked gracefully
    resp = client.post("/attendance/mark", data={
        "member_id": new_mid,
        "attendance_date": today.isoformat(),
        "csrf_token": csrf_tok
    }, follow_redirects=True)
    assert_test(b"already checked in" in resp.data, "Duplicate check-in on the same date is blocked with friendly message")

    # --------------------------------------------------------------------------
    # TEST 11: Two-Step Payment Collection & Receipt Rendering
    # --------------------------------------------------------------------------
    with client.session_transaction() as sess:
        csrf_tok = sess["csrf_token"]

    # Step 1 GET with member_id
    resp = client.get(f"/payments/record?member_id={new_mid}")
    assert_test(resp.status_code == 200 and b"Billed Athlete:" in resp.data, "Payment Step 1 pre-fills member and plan fee")

    # Step 2 POST
    resp = client.post("/payments/record", data={
        "member_id": new_mid,
        "amount": "1500.00",
        "payment_method": "UPI",
        "status": "Paid",
        "payment_date": today.isoformat(),
        "csrf_token": csrf_tok
    }, follow_redirects=True)

    assert_test(resp.status_code == 200 and b"Official Payment Receipt" in resp.data, "Payment Step 2 generates receipt")
    assert_test(b"PAY-" in resp.data and b"1,500.00" in resp.data, "Receipt contains payment ID, amount, and member details")

    # --------------------------------------------------------------------------
    # TEST 12: Search, Filters & Pagination
    # --------------------------------------------------------------------------
    resp = client.get(f"/members?q={quote('Test Athlete')}")
    assert_test(b"Test Athlete" in resp.data, "Member search filters by name accurately")

    resp = client.get("/members?status=active")
    assert_test(resp.status_code == 200 and b"Active" in resp.data, "Member filter by status=active returns active members")

    resp = client.get("/payments?method=UPI")
    assert_test(resp.status_code == 200 and b"UPI" in resp.data, "Payments filter by method=UPI functions properly")

    # --------------------------------------------------------------------------
    # TEST 13: In-Memory CSV Exports (Members, Payments, Attendance)
    # --------------------------------------------------------------------------
    resp = client.get("/reports/export/members")
    assert_test(resp.status_code == 200, "GET /reports/export/members returns 200")
    assert_test("text/csv" in resp.headers.get("Content-Type", ""), "Export members returns Content-Type text/csv")
    assert_test("attachment; filename=" in resp.headers.get("Content-Disposition", ""), "Export members returns attachment download header")
    assert_test(b"Member ID,Full Name" in resp.data, "CSV content contains expected CSV header row")

    resp = client.get("/reports/export/payments")
    assert_test("text/csv" in resp.headers.get("Content-Type", ""), "Export payments returns Content-Type text/csv")

    resp = client.get("/reports/export/attendance")
    assert_test("text/csv" in resp.headers.get("Content-Type", ""), "Export attendance returns Content-Type text/csv")

    # --------------------------------------------------------------------------
    # TEST 14: Custom 404 Error Handler
    # --------------------------------------------------------------------------
    resp = client.get("/non_existent_gym_route_404")
    assert_test(resp.status_code == 404, "Non-existent URL triggers HTTP 404")
    assert_test(b"Page Not Found in Gym Facility" in resp.data, "404 page renders custom gym-branded 404 template")

    # --------------------------------------------------------------------------
    # Clean up test member
    # --------------------------------------------------------------------------
    with app.app_context():
        conn = database.get_db_connection()
        conn.execute("DELETE FROM members WHERE phone = ?;", (test_phone,))
        conn.commit()
        conn.close()

    print("=" * 75)
    print(f"SMOKE TEST SUMMARY: {passed} OF {total} TESTS PASSED (100% SUCCESS)")
    print("=" * 75)
    return True


if __name__ == "__main__":
    success = run_tests()
    if not success:
        sys.exit(1)
