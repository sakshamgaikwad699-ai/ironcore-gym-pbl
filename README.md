# ⚡ Iron Core Gym Management System (PBL)

**SPPU Pune — B.Tech Artificial Intelligence & Data Science**  
**Project-Based Learning (PBL) Laboratory Coursework**  
**Academic Year:** 2026–2027  
**Technology Stack:** HTML5, CSS3, Python 3.11+ (Flask), SQLite3  
**Design Philosophy:** Strict Zero-JavaScript, Server-Side Rendered (SSR), Dark Fitness Theme  

---

## 📋 Table of Contents
1. [Project Overview](#-project-overview)
2. [Strict Technology Rules & Design Constraints](#-strict-technology-rules--design-constraints)
3. [Key Feature Breakdown](#-key-feature-breakdown)
4. [Project Structure](#-project-structure)
5. [Database Architecture & ASCII ER Diagram](#-database-architecture--ascii-er-diagram)
6. [Local Installation & Setup Guide](#-local-installation--setup-guide)
7. [Automated Verification (Smoke Test Suite)](#-automated-verification-smoke-test-suite)
8. [Production Deployment Guides](#-production-deployment-guides)
   - [Option A: PythonAnywhere Deployment (Recommended)](#option-a-pythonanywhere-deployment-recommended)
   - [Option B: Vercel Serverless Deployment](#option-b-vercel-serverless-deployment)
9. [Administrative Password & Security Management](#-administrative-password--security-management)
10. [Engineering Trade-offs & Limitations](#-engineering-trade-offs--limitations)
11. [Project Report Screenshots Checklist](#-project-report-screenshots-checklist)
12. [10 Likely Viva Questions & Faculty-Grade Answers](#-10-likely-viva-questions--faculty-grade-answers)

---

## 📌 Project Overview
The **Iron Core Gym Management System** is a full-stack, enterprise-grade web application engineered to run daily gym operations, subscriptions, staff payroll, athlete attendance, and financial ledgers.

Developed specifically for 2nd-year B.Tech students in AI & Data Science at Savitribai Phule Pune University (SPPU), this system serves as an exemplar of robust software engineering principles:
- **Clean Architecture:** Strict separation of data access (`database.py`), application routing and security (`app.py`), and presentation (`templates/` and `static/css/style.css`).
- **Defensive Engineering:** Zero JavaScript dependencies, zero third-party client libraries, zero ORM overhead, and 100% parameterized SQL execution.
- **Resilient Security:** Hand-crafted constant-time CSRF tokens, brute-force IP/username throttling, HTTPOnly cookies, and strict Content-Security-Policy (CSP) headers.

---

## 🛡️ Strict Technology Rules & Design Constraints

| Component | Standard Implemented | Rationale |
| :--- | :--- | :--- |
| **Backend Framework** | Flask 3.1.0+ (`Flask` only in `requirements.txt`) | Minimalist, auditable WSGI foundation with built-in Jinja2 templating and Werkzeug hashing. |
| **Database** | SQLite3 via standard library `sqlite3` | Zero driver dependencies. `PRAGMA foreign_keys = ON;` on every connection. |
| **Client Scripts** | **STRICT ZERO JAVASCRIPT** (`<script>` forbidden) | Zero XSS attack surface from scripts; 100% accessible; pure server-side deterministic state. |
| **Styling** | Hand-crafted CSS3 (`static/css/style.css`) | Custom dark fitness theme (`#0f0f0f` background, glowing red `#e50914` accents, zebra tables, card hover lifts). |
| **Mobile Drawer** | Pure CSS Checkbox Hack | Collapsible sidebar on mobile devices using hidden `<input type="checkbox">` and CSS sibling selectors. |
| **Visual Charts** | Pure CSS Progress Bars | Real-time 7-day attendance trends rendered using server-computed inline widths (`width: NN%`). |
| **Exports** | In-Memory CSV Streams (`io.StringIO` + `csv.writer`) | Zero disk footprint; no orphan files generated in filesystem; instant client downloads. |
| **Localization** | Timezone `Asia/Kolkata` (IST), Currency `INR (₹)` | Accurate Indian timezone offsets and financial formatting (`₹1,500.00`). |

---

## 🚀 Key Feature Breakdown

### 1. Administrative Authentication & Security
- **Werkzeug Cryptography:** Passwords stored using PBKDF2 with SHA-256 password hashing (`generate_password_hash` / `check_password_hash`).
- **Default Credentials:** Username: `admin` | Password: `password123` (promptly changeable in Settings).
- **Hand-Crafted CSRF Protection:** Cryptographic session tokens generated via `secrets.token_urlsafe(32)`. Verified on every `POST` request using `hmac.compare_digest` in `before_request`. Invalid tokens trigger HTTP 400.
- **Brute-Force Rate Limiting:** Consecutive failed logins are recorded in `login_attempts`. If a username accumulates 5 failures within 10 minutes, logins are blocked for 10 minutes.
- **Security Headers:** `Content-Security-Policy: default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline';`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: SAMEORIGIN`.

### 2. Live Operations Dashboard
- Real-time SQL aggregations: Total Members, Active Subscriptions, Expired Plans, Total Trainers, Total Revenue, This-Month Revenue, and Today's Attendance Check-ins.
- Highlights members whose plans expire in **≤ 7 days**, complete with days-remaining indicators and one-click quick renewal.
- Displays the 5 most recent member registrations with quick links to full profiles.

### 3. Member Lifecycle Management (CRUD)
- Sequential ID Generation: `MEM-1001`, `MEM-1002`, etc., derived from `MAX(CAST(SUBSTR(member_id, 5) AS INTEGER))` rather than volatile row counts.
- Profile Fields: Full Name, Age (12–90), Gender (Male/Female/Other), 10-digit Indian Mobile (`^[6-9]\d{9}$`), Email, Address, Plan ID, Start Date, Expiry Date.
- Dynamic Expiry Calculation: `start_date + timedelta(days=plan.duration_days)`.
- Smart Renewal: Extends validity from `max(today, current_expiry) + plan_duration`. Automatically writes a renewal receipt into the payments ledger.
- Safe Deletion: Redirects to `confirm_delete.html` detailing database cascade effects (`ON DELETE CASCADE` removes member payments and attendance).

### 4. Membership Plans & Packages
- 4 Out-of-the-box Plans:
  1. **Monthly Plan** (30 Days — ₹1,500.00)
  2. **Quarterly Plan** (90 Days — ₹4,000.00)
  3. **Half-Yearly Plan** (180 Days — ₹7,500.00)
  4. **Annual VIP Plan** (365 Days — ₹13,500.00)
- Foreign Key Integrity Protection: Deleting a plan that has assigned members is strictly blocked with an explanatory error notice.

### 5. Trainers & Coaching Staff
- Sequential ID Generation: `TRN-101`, `TRN-102`...
- Fields: Name, Specialization, Phone, Email, Experience (0–50 yrs), Monthly Salary, Availability (Full-time / Part-time).
- Search, filter, and payroll budget summation.

### 6. Two-Step Fee Collection & Printable Receipts
- Two-step server-side flow:
  - **Step 1:** Select member from directory -> auto-fills plan fee and duration.
  - **Step 2:** Choose payment method (UPI / Card / Cash), status (Paid / Pending), date -> generates receipt `PAY-5001...`.
- Printable Receipt (`/payments/receipt/<payment_id>`):
  - Formatted with gym branding, bill-to details, transaction mode, itemized breakdown.
  - Media print CSS renders a clean, ink-friendly receipt with a Ctrl+P shortcut hint.

### 7. Workout Attendance & Pure-CSS Visual Trends
- Daily Check-in Form: Records check-in time automatically using IST clock time (`HH:MM:SS`).
- Constraint Enforcement: `UNIQUE(member_id, attendance_date)` prevents duplicate check-ins on the same calendar day.
- Expired Member Safeguard: Members with expired plans cannot check in unless the administrator checks the override box `Allow Expired Member Check-in`.
- 7-Day Trend Chart: Pure CSS bar chart showing workout attendance fluctuations across the past week.

### 8. Audit Reports & In-Memory CSV Streams
- Generates filterable reports across date ranges, plans, and statuses.
- Dedicated streaming CSV endpoints that generate exports on-the-fly in RAM (`io.StringIO`):
  - `/reports/export/members`
  - `/reports/export/payments`
  - `/reports/export/attendance`

---

## 📂 Project Structure

```text
gym_management_system/
├── app.py                      # Core application: routing, CSRF, security headers, filters, logic
├── database.py                 # SQLite schema, indexes, seed data, environment path resolution
├── smoke_test.py               # 37 automated test assertions verifying the entire system
├── requirements.txt            # Strictly contains 'Flask'
├── README.md                   # Complete architectural, deployment, and viva documentation
├── gym.db                      # SQLite relational database (auto-created & persistent)
├── wsgi.py                     # WSGI entry point for PythonAnywhere ('application = app')
├── vercel.json                 # Serverless lambda configuration for Vercel deployment
├── api/
│   └── index.py                # Serverless bridge for Vercel ('from app import app')
├── .gitignore                  # Git ignore rules for bytecode, virtual environments, and caches
├── static/
│   └── css/
│       └── style.css           # Hand-crafted dark fitness theme & media print styles
└── templates/
    ├── base.html               # Master layout: sidebar, topbar, mobile drawer, flash banners
    ├── login.html              # Administrator authentication form
    ├── dashboard.html          # Operational dashboard with live metrics & expiring tables
    ├── members.html            # Member directory with search, filters, and pagination
    ├── add_member.html         # Athlete registration form with server-side validation
    ├── edit_member.html        # Member modification form with expiry recalculation option
    ├── member_details.html     # Comprehensive athlete profile, billing history, attendance log
    ├── membership_plans.html   # Plan list, member count distribution, add/edit form
    ├── trainers.html           # Coach roster, salary tracking, add/edit modal-free form
    ├── payments.html           # Two-step fee collection workflow and financial ledger
    ├── receipt.html            # Formal printable receipt with Ctrl+P styling
    ├── attendance.html         # Daily check-in form and pure-CSS 7-day bar chart
    ├── reports.html            # Operational audit summaries and CSV download buttons
    ├── settings.html           # Facility branding configuration & password change portal
    ├── confirm_delete.html     # Defensive deletion warning page highlighting CASCADE effects
    └── 404.html                # Branded 404 error page (zero stack traces exposed)
```

---

## 🗄️ Database Architecture & ASCII ER Diagram

All relational tables enforce strict data integrity rules, foreign key constraints (`PRAGMA foreign_keys = ON;`), and targeted indexes on search and filter columns.

```text
  +-----------------------------------+
  |               users               |
  +-----------------------------------+
  | *id            INTEGER (PK AUTO)  |
  |  username      TEXT (UNIQUE)      |
  |  password_hash TEXT               |
  |  created_at    TEXT               |
  +-----------------------------------+

  +-----------------------------------+
  |         membership_plans          |
  +-----------------------------------+
  | *id            INTEGER (PK AUTO)  |
  |  plan_name     TEXT (UNIQUE)      |
  |  duration_days INTEGER (CHECK >0) |
  |  price         REAL (CHECK >= 0)  |
  |  description   TEXT               |
  +-----------------+-----------------+
                    | 1
                    |
                    | N (ON DELETE RESTRICT)
  +-----------------v-----------------+
  |              members              |
  +-----------------------------------+
  | *id            INTEGER (PK AUTO)  |
  |  member_id     TEXT (UNIQUE)      |<--------------+
  |  full_name     TEXT               |               |
  |  age           INTEGER (12..90)   |               |
  |  gender        TEXT (CHECK IN)    |               |
  |  phone         TEXT               |               |
  |  email         TEXT               |               |
  |  address       TEXT               |               |
  |  reg_date      TEXT               |               |
  |  plan_id       INTEGER (FK)       |               |
  |  start_date    TEXT               |               |
  |  expiry_date   TEXT               |               |
  +--------+------------------+-------+               |
           | 1                | 1                     |
           |                  |                       |
           | N (CASCADE)      | N (CASCADE)           |
  +--------v----------+  +----v-------------------+   |
  |     payments      |  |       attendance       |   |
  +-------------------+  +------------------------+   |
  | *id         INT   |  | *id         INT        |   |
  |  payment_id TEXT  |  |  member_id  TEXT (FK)--+---+
  |  member_id  TEXT  |  |  att_date   TEXT       |
  |  amount     REAL  |  |  check_time TEXT       |
  |  method     TEXT  |  |  UNIQUE(member, date)  |
  |  date       TEXT  |  +------------------------+
  |  status     TEXT  |
  +-------------------+

  +-----------------------------------+       +-----------------------------------+
  |             trainers              |       |          login_attempts           |
  +-----------------------------------+       +-----------------------------------+
  | *id            INTEGER (PK AUTO)  |       | *id            INTEGER (PK AUTO)  |
  |  trainer_id    TEXT (UNIQUE)      |       |  identifier    TEXT               |
  |  full_name     TEXT               |       |  attempted_at  TEXT (TIMESTAMP)   |
  |  specializationTEXT               |       +-----------------------------------+
  |  phone         TEXT               |
  |  email         TEXT               |       +-----------------------------------+
  |  experience    INTEGER (0..50)    |       |             settings              |
  |  salary        REAL (CHECK >= 0)  |       +-----------------------------------+
  |  availability  TEXT (CHECK IN)    |       | *key           TEXT (PK)          |
  +-----------------------------------+       |  value         TEXT               |
                                              +-----------------------------------+
```

### Table Indexes
- `idx_members_search` on `members(member_id, full_name, phone, email)`
- `idx_members_expiry` on `members(expiry_date)`
- `idx_payments_member` on `payments(member_id)`
- `idx_payments_date` on `payments(payment_date)`
- `idx_attendance_date` on `attendance(attendance_date)`
- `idx_login_attempts` on `login_attempts(identifier, attempted_at)`

---

## 💻 Local Installation & Setup Guide

### Prerequisites
- Python 3.11, 3.12, or newer installed.
- Git (optional, for version control).

### Step-by-Step Instructions

1. **Open Terminal / Command Prompt:**
   Navigate to the project directory:
   ```bash
   cd "C:\GYM Management System"
   ```

2. **Verify Python Installation:**
   ```bash
   python --version
   ```

3. **Install Flask (Strict Single Dependency):**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify Database Auto-Creation:**
   Run the database initialization script (optional, as `app.py` runs this automatically on startup):
   ```bash
   python database.py
   ```
   *Output:* `Database initialized successfully at: .../gym.db`

5. **Start the Development Server:**
   ```bash
   python app.py
   ```
   *Output:*
   ```text
    * Serving Flask app 'app'
    * Debug mode: on
    * Running on http://127.0.0.1:5000
   ```

6. **Access the System:**
   - Open your web browser and navigate to: `http://127.0.0.1:5000`
   - Sign in using the default administrative credentials:
     - **Username:** `admin`
     - **Password:** `password123`

---

## 🧪 Automated Verification (Smoke Test Suite)

A comprehensive automated test suite is provided in `smoke_test.py`. It runs 37 distinct validation checks against the Flask application using Flask's native `test_client()`.

### Running the Test Suite
```bash
python smoke_test.py
```

### Expected Output
```text
===========================================================================
RUNNING SMOKE TEST SUITE: GYM MANAGEMENT SYSTEM
===========================================================================
 [PASS] Test 01: All 16 required templates exist (found 16)
 [PASS] Test 02: ZERO <script> tags present across all HTML templates
 [PASS] Test 03: ZERO inline on* event handlers in HTML templates
 [PASS] Test 04: GET / redirects to /login when unauthenticated
 [PASS] Test 05: GET /members redirects to /login when unauthenticated
 [PASS] Test 06: GET /reports redirects to /login when unauthenticated
 [PASS] Test 07: GET /login renders HTTP 200
 [PASS] Test 08: Login fails with bad password and displays flash error
 [PASS] Test 09: POST without CSRF token returns HTTP 400 Bad Request
 [PASS] Test 10: POST with forged CSRF token returns HTTP 400 Bad Request
 [PASS] Test 11: Default admin login succeeds and renders Dashboard
 [PASS] Test 12: Dashboard shows live aggregate metric cards
 [PASS] Test 13: CSP header strictly enforces script-src 'none'
 [PASS] Test 14: Member registration successfully processed
 [PASS] Test 15: Sequential ID generated starting with MEM-
 [PASS] Test 16: Member row exists in database with ID MEM-1013
 [PASS] Test 17: Plan 'Monthly Plan' duration matches 30 days correctly
 [PASS] Test 18: Plan 'Quarterly Plan' duration matches 90 days correctly
 [PASS] Test 19: Plan 'Half-Yearly Plan' duration matches 180 days correctly
 [PASS] Test 20: Plan 'Annual Plan' duration matches 365 days correctly
 [PASS] Test 21: Newly enrolled member with future expiry displays 'Active Membership' badge
 [PASS] Test 22: First attendance check-in succeeds
 [PASS] Test 23: Duplicate check-in on the same date is blocked with friendly message
 [PASS] Test 24: Payment Step 1 pre-fills member and plan fee
 [PASS] Test 25: Payment Step 2 generates receipt
 [PASS] Test 26: Receipt contains payment ID, amount, and member details
 [PASS] Test 27: Member search filters by name accurately
 [PASS] Test 28: Member filter by status=active returns active members
 [PASS] Test 29: Payments filter by method=UPI functions properly
 [PASS] Test 30: GET /reports/export/members returns 200
 [PASS] Test 31: Export members returns Content-Type text/csv
 [PASS] Test 32: Export members returns attachment download header
 [PASS] Test 33: CSV content contains expected CSV header row
 [PASS] Test 34: Export payments returns Content-Type text/csv
 [PASS] Test 35: Export attendance returns Content-Type text/csv
 [PASS] Test 36: Non-existent URL triggers HTTP 404
 [PASS] Test 37: 404 page renders custom gym-branded 404 template
===========================================================================
SMOKE TEST SUMMARY: 37 OF 37 TESTS PASSED (100% SUCCESS)
===========================================================================
```

---

## 🌐 Production Deployment Guides

### Option A: PythonAnywhere Deployment (Recommended)
PythonAnywhere provides a persistent Linux filesystem ideal for SQLite, ensuring your database records remain intact across web server reloads.

#### Click-by-Click Instructions:
1. **Create an Account:**
   - Register at [pythonanywhere.com](https://www.pythonanywhere.com/).
2. **Open Bash Console:**
   - On the PythonAnywhere Dashboard, click **Consoles** -> **Bash**.
3. **Upload or Clone Code:**
   ```bash
   git clone <YOUR_GITHUB_REPO_URL> gym_system
   cd gym_system
   ```
4. **Create Virtual Environment:**
   ```bash
   python3.11 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
5. **Configure Web App:**
   - Navigate to the **Web** tab.
   - Click **Add a new web app**.
   - Choose **Manual configuration** and select **Python 3.11**.
6. **Set Paths in Web Tab:**
   - **Source code:** `/home/<your-username>/gym_system`
   - **Working directory:** `/home/<your-username>/gym_system`
   - **Virtualenv path:** `/home/<your-username>/gym_system/venv`
7. **Configure WSGI Configuration File:**
   - On the **Web** tab, click the link to edit the **WSGI configuration file** (`/var/www/<your-username>_pythonanywhere_com_wsgi.py`).
   - Clear existing boilerplate and enter:
     ```python
     import sys
     path = '/home/<your-username>/gym_system'
     if path not in sys.path:
         sys.path.insert(0, path)

     from wsgi import application
     ```
   - Save the file.
8. **Reload and Launch:**
   - Click the green **Reload <your-username>.pythonanywhere.com** button.
   - Visit your live URL!

---

### Option B: Vercel Serverless Deployment
Vercel allows zero-cost instant serverless hosting using the included `vercel.json` and `api/index.py`.

#### Step-by-Step Instructions:
1. **Push Code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Deploy Iron Core Gym Management System"
   git branch -M main
   git remote add origin https://github.com/<your-username>/gym-management-system.git
   git push -u origin main
   ```
2. **Import into Vercel:**
   - Log into [vercel.com](https://vercel.com/) and click **Add New** -> **Project**.
   - Import your GitHub repository.
   - Leave build settings as default (Vercel automatically detects `vercel.json` and `@vercel/python`).
   - Click **Deploy**.
3. **Verify Deployment:**
   - Access your Vercel deployment URL (e.g., `https://gym-management-system.vercel.app`).
   - Sign in with `admin` / `password123`.

> [!WARNING]
> **Vercel Ephemeral Storage Notice:**
> Vercel Lambda functions operate in read-only containers with ephemeral storage restricted to `/tmp`. `database.py` automatically detects the `VERCEL` environment variable and writes to `/tmp/gym.db`. Any new records added on Vercel will reset when the serverless function becomes idle. For permanent production data persistence, use **PythonAnywhere** or attach an external database driver.

---

## 🔑 Administrative Password & Security Management

### Changing the Admin Password
1. Log into the system at `/login`.
2. In the left navigation menu, click **⚙️ System Settings**.
3. Scroll to the **🔐 Administrator Credentials** panel.
4. Input:
   - Your **Current Password** (`password123` for first-time login).
   - Your **New Password** (minimum 8 characters).
   - Confirm your **New Password**.
5. Click **Update Admin Password**.
6. The system encrypts the new password using PBKDF2 SHA-256 and commits it to the `users` table.

---

## ⚖️ Engineering Trade-offs & Limitations

1. **Zero-JavaScript Constraint:**
   - *Advantage:* Complete immunity to client-side DOM injection, zero JavaScript vulnerabilities, ultra-lightweight page weight (< 15 KB), and deterministic server-side state.
   - *Trade-off:* All search filters and form submissions require a standard HTTP GET/POST cycle. Form validation errors re-render the page rather than displaying inline client-side toasts.
2. **SQLite Concurrent Access:**
   - *Advantage:* Portable single-file storage with zero setup, zero memory daemon overhead, and immediate ACID compliance.
   - *Trade-off:* SQLite uses file-level locking during writes. For facilities exceeding 50,000 members with simultaneous multi-admin cashier terminals, PostgreSQL would be preferred.
3. **Vercel Ephemeral `/tmp`:**
   - Because SQLite writes to disk, serverless platforms like Vercel discard disk changes after lambda instances sleep. PythonAnywhere provides true persistent storage.

---

## 📸 Project Report Screenshots Checklist

For the SPPU PBL examination documentation and laboratory journal, take screenshots of the following pages:

- [ ] **Login Portal (`/login`):** Showing branding, inputs, and security notice.
- [ ] **Executive Dashboard (`/`):** Displaying all 7 live metric cards and expiring memberships table.
- [ ] **Member Directory (`/members`):** Demonstrating search query and status filter badges.
- [ ] **Member Enrollment (`/members/add`):** Illustrating field validation and plan selection.
- [ ] **Athlete Dossier (`/members/MEM-1001`):** Profile card with payment history and attendance tables.
- [ ] **Membership Packages (`/plans`):** Displaying active plans and assigned member counts.
- [ ] **Trainers Roster (`/trainers`):** Showing coaches, specialties, and monthly salary budget.
- [ ] **Fee Payment Workflow (`/payments` & `/payments/record`):** Step 1 & Step 2 billing flow.
- [ ] **Printable Receipt (`/payments/receipt/PAY-5001`):** Receipt layout with print notification banner.
- [ ] **Attendance Tracker (`/attendance`):** Daily check-in log and the pure-CSS 7-day attendance bar chart.
- [ ] **Audit Reports (`/reports`):** Revenue breakdown by month and CSV download buttons.
- [ ] **Security Settings (`/settings`):** Password management and gym facility branding forms.
- [ ] **Deletion Guard (`/members/MEM-10xx/delete`):** Cascade warning on the deletion confirmation page.
- [ ] **Custom 404 (`/non_existent_page`):** Dark-themed error page without stack traces.

---

## 🎓 10 Likely Viva Questions & Faculty-Grade Answers

#### Q1: Why did you not use an ORM like SQLAlchemy?
> **Answer:** In high-integrity database systems, an ORM abstracts away SQL generation, which often leads to the N+1 query problem, unexpected query overhead, and hidden migrations. By utilizing Python's built-in `sqlite3` module with explicit parameterized SQL (`?` placeholders), every query execution plan is transparent, predictable, and provably secure against SQL injection.

#### Q2: How does your CSRF protection mechanism function without Flask-WTF?
> **Answer:** We implemented the Synchronizer Token Pattern manually. Upon session creation, `secrets.token_urlsafe(32)` generates a cryptographically secure random token stored in the server-side Flask session. Every HTML form embeds this as a hidden input. On every `POST` request, the `before_request` hook validates the submitted token against the session token using `hmac.compare_digest()`, which prevents timing attacks.

#### Q3: How is brute-force protection implemented for authentication?
> **Answer:** We maintain a dedicated `login_attempts` table tracking username identifiers and IST timestamps. When a login attempt fails, an entry is inserted. Before validating password credentials, the system checks whether the username has accumulated 5 or more failed attempts within the trailing 10-minute window (`attempted_at >= now - 10 minutes`). If so, authentication is locked for 10 minutes.

#### Q4: How is mobile responsiveness achieved with ZERO JavaScript?
> **Answer:** We utilized the CSS-only Checkbox Hack. An invisible HTML checkbox (`<input type="checkbox" id="sidebar-toggle">`) precedes the sidebar markup. When a user taps the `<label for="sidebar-toggle">` hamburger icon on mobile screens, the `:checked` pseudo-class triggers the sibling selector `.sidebar-toggle-checkbox:checked ~ .app-container .sidebar`, sliding the sidebar into the viewport via CSS `transform: translateX(0)`.

#### Q5: How is the visual 7-day attendance chart rendered without Chart.js or JavaScript?
> **Answer:** The attendance trend is rendered using semantic HTML and CSS. The server calculates daily attendance counts, determines the maximum count over the 7 days, and computes the proportional percentage (`count / max * 100`). This percentage is injected into the HTML markup as an inline style `style="width: {{ day.pct }}%"`. The CSS rules style the background track, linear gradient fill, and transitions purely within CSS.

#### Q6: Why did you use `MAX()` numeric suffix for ID generation instead of `COUNT(*)`?
> **Answer:** Using `COUNT(*)` or row counts for ID generation causes primary key collisions when records are deleted (e.g., if you have 10 members and delete member 5, `COUNT(*) + 1` produces 10, colliding with the existing 10th member). By querying `MAX(CAST(SUBSTR(member_id, 5) AS INTEGER))`, we identify the highest numeric suffix ever assigned and increment it by 1, guaranteeing strict sequence monotonicity.

#### Q7: How does your membership renewal logic handle expired vs active memberships?
> **Answer:** The renewal route dynamically sets the validity base date using Python's `max(today, current_expiry)`. If a member renews before expiration, their new expiry is extended from their current expiry date so they do not lose remaining prepaid days. If their membership has already lapsed, the extension starts from today's date.

#### Q8: What is `ON DELETE CASCADE` and why is it important in your schema?
> **Answer:** In relational databases, child records (such as payments and attendance entries) have foreign keys referencing the parent member ID. Setting `ON DELETE CASCADE` ensures that if a member is permanently deleted, SQLite automatically removes all associated payments and attendance logs, preventing orphaned records. We explicitly execute `PRAGMA foreign_keys = ON;` on every connection to ensure SQLite enforces this constraint.

#### Q9: How are CSV exports generated without writing files to the server's storage?
> **Answer:** We generate the CSV content in memory using Python's `io.StringIO` buffer combined with the standard `csv.writer` module. Once the query results are formatted into rows, the buffer string is returned as a Flask `Response` object with MIME type `text/csv` and an HTTP `Content-Disposition: attachment; filename=...` header, streaming the file directly to the user's browser.

#### Q10: Why did you enforce Content-Security-Policy with `script-src 'none'`?
> **Answer:** Setting `script-src 'none'` instructs the web browser to refuse execution of all JavaScript, including inline `<script>` tags, event handlers (`onclick`, etc.), and external scripts. This ensures defense-in-depth: even if untrusted user input somehow bypassed Jinja2 autoescaping, no malicious script could ever execute in the browser.
