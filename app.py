import os
import sqlite3
import secrets
import hmac
import time
import datetime as dt
from functools import wraps

from flask import (Flask, g, request, redirect, url_for, session, flash,
                   render_template_string, abort, jsonify, send_from_directory)
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("SECRET_KEY"):
    print("OGOHLANTIRISH: SECRET_KEY o'rnatilmagan; server qayta ishga tushsa sessiyalar tugaydi.")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "1") == "1",
    MAX_CONTENT_LENGTH=11 * 1024 * 1024,   # fayl yuklash uchun (10 MB + zaxira)
)
UPLOAD_DIR = os.path.abspath(os.environ.get("UPLOAD_DIR", "uploads"))
MAX_FILE_NAME = 120
ALLOWED_EXT = {".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff", ".png": b"\x89PNG",
               ".gif": b"GIF8", ".webp": b"RIFF", ".pdf": b"%PDF"}
DB = os.environ.get("DB_PATH", "guruh.db")
MIN_PASSWORD = 6
LOGIN_WINDOW = 15 * 60      # soniya
LOGIN_MAX_FAILS = 5
_failed_logins = {}         # {login: [vaqt, ...]} — bitta jarayon uchun yetarli

STATUS = {
    "yangi": "Yangi",
    "jarayonda": "Jarayonda",
    "topshirildi": "Topshirildi (tekshirilmoqda)",
    "qabul": "Qabul qilindi",
    "qaytarildi": "Qaytarildi",
}
ATT = {"keldi": "Keldi", "kelmadi": "Kelmadi", "sababli": "Sababli"}


def now():
    return dt.datetime.now().isoformat(timespec="minutes")


def today():
    return dt.date.today().isoformat()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    d = g.pop("db", None)
    if d is not None:
        d.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS tasks(
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    due_date TEXT,
    assignee_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'yangi',
    submission_text TEXT,
    submission_link TEXT,
    submitted_at TEXT,
    feedback TEXT,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attendance(
    id INTEGER PRIMARY KEY,
    day TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    note TEXT,
    UNIQUE(day, user_id));
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS uploads(
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    day TEXT,
    note TEXT,
    orig TEXT NOT NULL,
    stored TEXT NOT NULL,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS announcements(
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    urgent INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL);
"""


def init_db():
    with sqlite3.connect(DB) as c:
        c.executescript(SCHEMA)
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            c.execute(
                "INSERT INTO users(username, full_name, password_hash, role) VALUES(?,?,?,?)",
                (os.environ.get("ADMIN_USER", "admin"), "Administrator",
                 generate_password_hash(os.environ.get("ADMIN_PASS", "admin123")),
                 "admin"))


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()


def login_required(admin=False):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            u = current_user()
            if u is None:
                return redirect(url_for("login"))
            if admin and u["role"] != "admin":
                abort(403)
            g.user = u
            return f(*args, **kwargs)
        return wrapper
    return deco


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, description="Sahifani yangilab qayta urinib ko‘ring.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "form-action 'self'; frame-ancestors 'none'")
    return resp


def clip(value, limit):
    return (value or "").strip()[:limit]


def valid_date(value):
    if not value:
        return None
    try:
        return dt.date.fromisoformat(value).isoformat()
    except ValueError:
        return None


def login_blocked(login):
    cutoff = time.time() - LOGIN_WINDOW
    fails = [t for t in _failed_logins.get(login, []) if t > cutoff]
    _failed_logins[login] = fails
    return len(fails) >= LOGIN_MAX_FAILS


BASE = """<!doctype html><html lang="uz"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · Guruh boshqaruvi</title>
<style>
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6fa;color:#1d2433;font-size:15px;line-height:1.4}
header{background:#1e3a5f;color:#fff;padding:10px 14px;display:flex;flex-wrap:wrap;gap:4px 10px;align-items:center;justify-content:space-between}
header b{font-size:17px;padding:6px 0}
header nav{display:flex;flex-wrap:wrap;gap:2px}
header a{color:#cfe2ff;text-decoration:none;font-size:14px;padding:8px 9px;display:inline-block;border-radius:6px}
header a:hover,header a:focus{background:rgba(255,255,255,.12)}
main{max-width:980px;margin:16px auto;padding:0 12px}
.card{background:#fff;border-radius:10px;padding:16px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:0}
h1{font-size:21px;margin:4px 0 12px}
h3{margin:16px 0 8px;font-size:17px}
table{width:100%;border-collapse:collapse;font-size:14px;display:block;overflow-x:auto;-webkit-overflow-scrolling:touch}
th,td{padding:9px 8px;border-bottom:1px solid #e6e9f0;text-align:left;vertical-align:top}
th{white-space:nowrap}
input,select,textarea{width:100%;max-width:100%;padding:10px;border:1px solid #c9d1de;border-radius:7px;font-size:16px;margin:4px 0 10px;font-family:inherit;background:#fff}
input[type=radio],input[type=checkbox]{width:20px;height:20px;margin:0 6px 0 0;padding:0;accent-color:#1e3a5f;flex:none}
label{display:block}
button,.btn{background:#1e3a5f;color:#fff;border:0;padding:10px 16px;min-height:42px;border-radius:7px;font-size:15px;cursor:pointer;text-decoration:none;display:inline-block;font-family:inherit}
button.red,.btn.red{background:#b42318}
button.light,.btn.light{background:#e6e9f0;color:#1d2433}
.badge{display:inline-block;padding:3px 9px;border-radius:99px;font-size:12px;background:#e6e9f0;white-space:nowrap}
.badge.ok{background:#d1fadf;color:#05603a}
.badge.bad{background:#fee4e2;color:#b42318}
.flash{background:#ecfdf3;color:#05603a;padding:10px;border-radius:7px;margin-bottom:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.addform{display:grid;grid-template-columns:repeat(3,1fr) auto;gap:10px;align-items:end}
.addform label{margin:0}
.addform input{margin:4px 0 0}
.inline{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0 6px 6px 0}
.inline input{width:150px;margin:0}
.radios{display:flex;flex-wrap:wrap;gap:6px 14px}
.radios label{display:inline-flex;align-items:center;min-height:44px;padding-right:6px;white-space:nowrap;cursor:pointer}
td a{display:inline-block;padding:6px 0;min-height:30px}
.chatlog{height:min(420px,55vh);overflow-y:auto;background:#f8fafc;border-radius:8px;padding:10px;margin-bottom:10px}
.chatform{display:flex;gap:8px;align-items:flex-end}
.chatform textarea{margin:0}
.chatform button{flex:none}
.stat{font-size:26px;font-weight:700}
.muted{color:#667085;font-size:13px}
.ann{border-left:6px solid #1e3a5f}
.ann.urgent{border-left-color:#b42318;background:#fff5f4}
@media(max-width:700px){
  h1{font-size:19px}
  .addform{grid-template-columns:1fr}
  .addform button{width:100%}
  .card{padding:14px}
  main{padding:0 10px}
  .inline input{width:100%}
  .inline,.inline button{width:100%}
  header a{padding:9px 8px}
}
@media(prefers-reduced-motion:no-preference){html{scroll-behavior:smooth}}
</style></head><body>
{% if user %}<header><b>Guruh boshqaruvi</b><nav>
<a href="{{ url_for('dashboard') }}">Bosh sahifa</a>
{% if user.role=='admin' %}
<a href="{{ url_for('members') }}">A'zolar</a>
<a href="{{ url_for('tasks') }}">Topshiriqlar</a>
<a href="{{ url_for('attendance') }}">Yo‘qlama</a>
<a href="{{ url_for('stats') }}">Statistika</a>
{% else %}
<a href="{{ url_for('my_tasks') }}">Mening topshiriqlarim</a>
{% endif %}
<a href="{{ url_for('uploads') }}">Yuklamalar</a>
<a href="{{ url_for('chat') }}">Chat</a>
<a href="{{ url_for('password') }}">Parol</a>
<a href="{{ url_for('logout') }}">Chiqish</a>
</nav></header>{% endif %}
<main>
{% for a in ann %}<div class="card ann {{ 'urgent' if a.urgent else '' }}">
<b>{{ 'MUHIM: ' if a.urgent else 'E‘lon: ' }}</b>{{ a.text }}
<div class="muted">{{ a.created_at[:16].replace('T',' ') }}</div></div>{% endfor %}
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{{ content }}
</main>
<script>
document.querySelectorAll('form[method="post"]').forEach(function (f) {
  var i = document.createElement('input');
  i.type = 'hidden'; i.name = 'csrf'; i.value = '{{ csrf_token() }}';
  f.appendChild(i);
});
</script>
</body></html>"""


def page(tpl, title, **ctx):
    user = g.get("user")
    ann = []
    if user is not None:
        ann = db().execute(
            "SELECT * FROM announcements ORDER BY id DESC LIMIT 3").fetchall()
    body = render_template_string(tpl, user=user, **ctx)
    return render_template_string(BASE, title=title, user=user, ann=ann,
                                  content=Markup(body))


# ---------- Auth ----------

LOGIN = """<div class="card" style="max-width:380px;margin:40px auto">
<h1>Kirish</h1>
<form method="post"><label>Login</label><input name="username" required autofocus>
<label>Parol</label><input type="password" name="password" required>
<button>Kirish</button></form></div>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_name = clip(request.form.get("username"), 64)
        if login_blocked(login_name):
            flash("Juda ko‘p noto‘g‘ri urinish. 15 daqiqadan so‘ng qayta urinib ko‘ring.")
            return page(LOGIN, "Kirish"), 429
        u = db().execute("SELECT * FROM users WHERE username=? AND active=1",
                         (login_name,)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            _failed_logins.pop(login_name, None)
            session.clear()
            session["uid"] = u["id"]
            return redirect(url_for("dashboard"))
        _failed_logins.setdefault(login_name, []).append(time.time())
        flash("Login yoki parol noto‘g‘ri")
    return page(LOGIN, "Kirish")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


PASSWORD = """<div class="card" style="max-width:420px"><h1>Parolni o‘zgartirish</h1>
<form method="post"><label>Eski parol</label><input type="password" name="old" required>
<label>Yangi parol (kamida 6 belgi)</label><input type="password" name="new" required>
<button>Saqlash</button></form></div>"""


@app.route("/password", methods=["GET", "POST"])
@login_required()
def password():
    if request.method == "POST":
        if not check_password_hash(g.user["password_hash"], request.form.get("old", "")):
            flash("Eski parol noto‘g‘ri")
        elif len(request.form.get("new", "")) < 6:
            flash("Yangi parol kamida 6 belgidan iborat bo‘lsin")
        else:
            d = db()
            d.execute("UPDATE users SET password_hash=? WHERE id=?",
                      (generate_password_hash(request.form["new"]), g.user["id"]))
            d.commit()
            flash("Parol o‘zgartirildi")
            return redirect(url_for("dashboard"))
    return page(PASSWORD, "Parol")


# ---------- Bosh sahifa ----------

HOME = """<h1>Bosh sahifa</h1>
<div class="grid">
<div class="card"><div class="muted">Faol a'zolar</div><div class="stat">{{ s.members }}</div></div>
<div class="card"><div class="muted">Ochiq topshiriqlar</div><div class="stat">{{ s.open }}</div></div>
<div class="card"><div class="muted">Tekshiruvni kutmoqda</div><div class="stat">{{ s.check }}</div></div>
<div class="card"><div class="muted">Muddati o‘tgan</div><div class="stat">{{ s.overdue }}</div></div>
</div>
<div class="card"><b>Bugungi yo‘qlama ({{ today }})</b>
{% if s.marked %}<p>Belgilangan: {{ s.marked }} ta. Kelmaganlar: {{ s.absent }} ta.</p>
{% else %}<p class="muted">Bugun hali yo‘qlama qilinmagan.</p>{% endif %}
<a class="btn" href="{{ url_for('attendance') }}">Yo‘qlama qilish</a>
<a class="btn light" href="{{ url_for('tasks') }}">Topshiriq berish</a></div>
<div class="card"><b>E‘lon yuborish</b>
<form method="post" action="{{ url_for('announce') }}">
<textarea name="text" rows="2" required></textarea>
<label><input type="checkbox" name="urgent" style="width:auto"> Muhim (qizil rangda)</label>
<button>Joylash</button></form></div>"""


@app.route("/")
@login_required()
def dashboard():
    if g.user["role"] != "admin":
        return redirect(url_for("my_tasks"))
    d = db()
    t = today()
    s = dict(
        members=d.execute("SELECT COUNT(*) FROM users WHERE role='member' AND active=1").fetchone()[0],
        open=d.execute("SELECT COUNT(*) FROM tasks WHERE status IN ('yangi','jarayonda','qaytarildi')").fetchone()[0],
        check=d.execute("SELECT COUNT(*) FROM tasks WHERE status='topshirildi'").fetchone()[0],
        overdue=d.execute("SELECT COUNT(*) FROM tasks WHERE status!='qabul' AND due_date<?", (t,)).fetchone()[0],
        marked=d.execute("SELECT COUNT(*) FROM attendance WHERE day=?", (t,)).fetchone()[0],
        absent=d.execute("SELECT COUNT(*) FROM attendance WHERE day=? AND status='kelmadi'", (t,)).fetchone()[0],
    )
    return page(HOME, "Bosh sahifa", s=s, today=t)


@app.route("/announce", methods=["POST"])
@login_required(admin=True)
def announce():
    d = db()
    text = clip(request.form.get("text"), 500)
    if not text:
        flash("E‘lon matni bo‘sh bo‘lmasligi kerak")
        return redirect(url_for("dashboard"))
    d.execute("INSERT INTO announcements(text, urgent, created_at) VALUES(?,?,?)",
              (text, 1 if request.form.get("urgent") else 0, now()))
    d.commit()
    flash("E‘lon joylandi")
    return redirect(url_for("dashboard"))


# ---------- A'zolar ----------

MEMBERS = """<div class="card"><h1>Qo‘shish</h1>
<form method="post" class="addform">
<input type="hidden" name="action" value="add">
<div><label>Ism familiya</label><input name="full_name" required></div>
<div><label>Login</label><input name="username" required></div>
<div><label>Parol</label><input name="password" required></div>
<div><button>Qo‘shish</button></div></form></div>
<div class="card"><h1>A'zolar</h1>
<table><tr><th>Ism</th><th>Login</th><th>Holat</th><th>Amallar</th></tr>
{% for r in rows %}<tr><td>{{ r.full_name }}</td><td>{{ r.username }}</td>
<td>{% if r.active %}<span class="badge ok">Faol</span>{% else %}<span class="badge">Nofaol</span>{% endif %}</td>
<td>
<form method="post" class="inline">
<input type="hidden" name="action" value="reset"><input type="hidden" name="id" value="{{ r.id }}">
<input name="password" placeholder="Yangi parol" required>
<button class="light">Parolni yangilash</button></form>
<form method="post" class="inline">
<input type="hidden" name="action" value="toggle"><input type="hidden" name="id" value="{{ r.id }}">
<button class="light">{% if r.active %}Vaqtincha o‘chirish{% else %}Faollashtirish{% endif %}</button></form>
<form method="post" class="inline" onsubmit="return confirm('A‘zo va uning topshiriqlari o‘chirilsinmi?')">
<input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{{ r.id }}">
<button class="red">O‘chirish</button></form>
</td></tr>{% else %}<tr><td colspan="4" class="muted">A'zolar yo‘q</td></tr>{% endfor %}
</table></div>"""


@app.route("/members", methods=["GET", "POST"])
@login_required(admin=True)
def members():
    d = db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            username = clip(request.form.get("username"), 32)
            full_name = clip(request.form.get("full_name"), 100)
            password_in = request.form.get("password", "")
            if not username or not full_name:
                flash("Ism va login bo‘sh bo‘lmasligi kerak")
            elif len(password_in) < MIN_PASSWORD:
                flash(f"Parol kamida {MIN_PASSWORD} belgidan iborat bo‘lsin")
            else:
                try:
                    d.execute("INSERT INTO users(username, full_name, password_hash, role) VALUES(?,?,?,'member')",
                              (username, full_name, generate_password_hash(password_in)))
                    d.commit()
                    flash("A‘zo qo‘shildi")
                except sqlite3.IntegrityError:
                    flash("Bu login band")
        elif action == "reset":
            password_in = request.form.get("password", "")
            if len(password_in) < MIN_PASSWORD:
                flash(f"Parol kamida {MIN_PASSWORD} belgidan iborat bo‘lsin")
            else:
                d.execute("UPDATE users SET password_hash=? WHERE id=? AND role='member'",
                          (generate_password_hash(password_in), request.form.get("id")))
                d.commit()
                flash("Parol yangilandi")
        elif action == "toggle":
            d.execute("UPDATE users SET active=1-active WHERE id=? AND role='member'", (request.form["id"],))
            d.commit()
        elif action == "delete":
            uid = request.form["id"]
            d.execute("DELETE FROM attendance WHERE user_id=?", (uid,))
            d.execute("DELETE FROM tasks WHERE assignee_id=?", (uid,))
            d.execute("DELETE FROM users WHERE id=? AND role='member'", (uid,))
            d.commit()
            flash("A‘zo o‘chirildi")
        return redirect(url_for("members"))
    rows = d.execute("SELECT * FROM users WHERE role='member' ORDER BY full_name").fetchall()
    return page(MEMBERS, "A'zolar", rows=rows)


# ---------- Topshiriqlar ----------

TASKS = """<div class="card"><h1>Yangi topshiriq</h1>
<form method="post"><label>Sarlavha</label><input name="title" required>
<label>Tavsif</label><textarea name="description" rows="3"></textarea>
<label>Muddat</label><input type="date" name="due_date">
<label>Mas'ul a'zo</label>
<select name="assignee_id" required>{% for m in members %}<option value="{{ m.id }}">{{ m.full_name }}</option>{% endfor %}</select>
<button>Topshiriq berish</button></form></div>
<div class="card"><h1>Topshiriqlar</h1>
<table><tr><th>Sarlavha</th><th>A'zo</th><th>Muddat</th><th>Holat</th></tr>
{% for r in rows %}<tr><td><a href="{{ url_for('task_detail', tid=r.id) }}">{{ r.title }}</a></td>
<td>{{ r.assignee }}</td>
<td>{{ r.due_date or '—' }}
{% if r.due_date and r.due_date < today and r.status!='qabul' %}<span class="badge bad">Kechikkan</span>{% endif %}</td>
<td><span class="badge">{{ STATUS[r.status] }}</span></td></tr>
{% else %}<tr><td colspan="4" class="muted">Hali topshiriq yo‘q</td></tr>{% endfor %}</table></div>"""


@app.route("/tasks", methods=["GET", "POST"])
@login_required(admin=True)
def tasks():
    d = db()
    if request.method == "POST":
        title = clip(request.form.get("title"), 200)
        assignee = d.execute("SELECT id FROM users WHERE id=? AND role='member' AND active=1",
                             (request.form.get("assignee_id"),)).fetchone()
        if not title:
            flash("Sarlavha bo‘sh bo‘lmasligi kerak")
        elif assignee is None:
            flash("Mas'ul a'zo topilmadi")
        else:
            d.execute("INSERT INTO tasks(title, description, due_date, assignee_id, created_at) VALUES(?,?,?,?,?)",
                      (title, clip(request.form.get("description"), 2000),
                       valid_date(request.form.get("due_date")), assignee["id"], now()))
            d.commit()
            flash("Topshiriq berildi")
        return redirect(url_for("tasks"))
    rows = d.execute("""SELECT t.*, u.full_name AS assignee FROM tasks t
                        JOIN users u ON u.id=t.assignee_id ORDER BY t.created_at DESC""").fetchall()
    members_list = d.execute("SELECT id, full_name FROM users WHERE role='member' AND active=1 ORDER BY full_name").fetchall()
    return page(TASKS, "Topshiriqlar", rows=rows, members=members_list, today=today(), STATUS=STATUS)


TASK = """<div class="card"><h1>{{ t.title }}</h1>
<p>{{ t.description or '' }}</p>
<p class="muted">Mas'ul: {{ t.assignee }} · Muddat: {{ t.due_date or 'belgilanmagan' }} ·
Holat: <span class="badge">{{ STATUS[t.status] }}</span></p></div>
{% if t.submitted_at %}<div class="card" style="background:#f8fafc">
<b>A'zo javobi</b> <span class="muted">{{ t.submitted_at[:16].replace('T',' ') }}</span>
<p>{{ t.submission_text or '' }}</p>
{% if t.submission_link %}<p><a href="{{ t.submission_link }}" target="_blank" rel="noopener">Havola</a></p>{% endif %}
</div>{% endif %}
{% if is_admin %}<div class="card"><h1>Tekshiruv</h1>
<form method="post"><label>Izoh</label><textarea name="feedback" rows="2">{{ t.feedback or '' }}</textarea>
<button name="action" value="accept">Qabul qilish</button>
<button name="action" value="return" class="light">Qaytarish</button>
<button name="action" value="delete" class="red" onclick="return confirm('Topshiriq o‘chirilsinmi?')">O‘chirish</button>
</form></div>
{% else %}
{% if t.feedback %}<div class="card"><b>Rahbar izohi:</b> {{ t.feedback }}</div>{% endif %}
{% if t.status!='qabul' %}<div class="card"><h1>Javob yuborish</h1>
<form method="post"><label>Matn</label><textarea name="text" rows="4">{{ t.submission_text or '' }}</textarea>
<label>Havola (ixtiyoriy)</label><input name="link" placeholder="https://..." value="{{ t.submission_link or '' }}">
<button>Yuborish</button></form></div>{% endif %}
{% endif %}"""


@app.route("/tasks/<int:tid>", methods=["GET", "POST"])
@login_required()
def task_detail(tid):
    d = db()
    t = d.execute("""SELECT t.*, u.full_name AS assignee FROM tasks t
                     JOIN users u ON u.id=t.assignee_id WHERE t.id=?""", (tid,)).fetchone()
    if t is None:
        abort(404)
    is_admin = g.user["role"] == "admin"
    if not is_admin and t["assignee_id"] != g.user["id"]:
        abort(403)
    if request.method == "POST":
        if is_admin:
            action = request.form.get("action")
            if action == "delete":
                d.execute("DELETE FROM tasks WHERE id=?", (tid,))
                d.commit()
                flash("Topshiriq o‘chirildi")
                return redirect(url_for("tasks"))
            if action in ("accept", "return"):
                status = "qabul" if action == "accept" else "qaytarildi"
                d.execute("UPDATE tasks SET status=?, feedback=? WHERE id=?",
                          (status, clip(request.form.get("feedback"), 2000), tid))
                flash("Saqlandi")
        else:
            if t["status"] == "qabul":
                abort(400)
            link = clip(request.form.get("link"), 500)
            if link and not link.startswith(("http://", "https://")):
                link = ""
            text = clip(request.form.get("text"), 5000)
            if not text and not link:
                flash("Matn yoki havolani kiriting")
                return redirect(url_for("task_detail", tid=tid))
            d.execute("""UPDATE tasks SET submission_text=?, submission_link=?, submitted_at=?,
                         status='topshirildi' WHERE id=?""",
                      (text, link, now(), tid))
            flash("Javobingiz yuborildi")
        d.commit()
        return redirect(url_for("task_detail", tid=tid))
    return page(TASK, t["title"], t=t, is_admin=is_admin, STATUS=STATUS)


MY = """<div class="card"><h1>Mening topshiriqlarim</h1>
<table><tr><th>Topshiriq</th><th>Muddat</th><th>Holat</th></tr>
{% for r in rows %}<tr><td><a href="{{ url_for('task_detail', tid=r.id) }}">{{ r.title }}</a></td>
<td>{{ r.due_date or '—' }}
{% if r.due_date and r.due_date < today and r.status!='qabul' %}<span class="badge bad">Kechikkan</span>{% endif %}</td>
<td><span class="badge">{{ STATUS[r.status] }}</span></td></tr>
{% else %}<tr><td colspan="3" class="muted">Topshiriq yo‘q</td></tr>{% endfor %}</table></div>
<div class="card"><h1>Mening yo‘qlamam (so‘nggi 30 kun)</h1>
<table><tr><th>Sana</th><th>Holat</th><th>Izoh</th></tr>
{% for a in att %}<tr><td>{{ a.day }}</td><td>{{ ATT[a.status] }}</td><td>{{ a.note or '' }}</td></tr>
{% else %}<tr><td colspan="3" class="muted">Yozuv yo‘q</td></tr>{% endfor %}</table></div>"""


@app.route("/my-tasks")
@login_required()
def my_tasks():
    d = db()
    rows = d.execute("""SELECT * FROM tasks WHERE assignee_id=?
                        ORDER BY due_date IS NULL, due_date, id DESC""", (g.user["id"],)).fetchall()
    att = d.execute("""SELECT day, status, note FROM attendance WHERE user_id=?
                       ORDER BY day DESC LIMIT 30""", (g.user["id"],)).fetchall()
    return page(MY, "Mening topshiriqlarim", rows=rows, att=att, today=today(), STATUS=STATUS, ATT=ATT)


# ---------- Yo'qlama ----------

ATTEND = """<div class="card"><h1>Kunlik yo‘qlama</h1>
<form method="get" style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
<div><label>Sana</label><input type="date" name="day" value="{{ day }}" style="width:auto"></div>
<button class="light">Ko‘rish</button></form></div>
<div class="card"><form method="post">
<input type="hidden" name="day" value="{{ day }}">
<table><tr><th>A'zo</th><th>Holat</th><th>Izoh</th></tr>
{% for m in members %}<tr><td>{{ m.full_name }}</td>
<td><div class="radios">{% for k, v in ATT.items() %}<label>
<input type="radio" name="s{{ m.id }}" value="{{ k }}" {% if m.status==k %}checked{% endif %}>{{ v }}</label>{% endfor %}</div></td>
<td><input name="n{{ m.id }}" value="{{ m.note or '' }}" style="margin:0"></td></tr>
{% else %}<tr><td colspan="3" class="muted">Faol a‘zolar yo‘q</td></tr>{% endfor %}</table>
<button>Saqlash</button></form></div>"""


@app.route("/attendance", methods=["GET", "POST"])
@login_required(admin=True)
def attendance():
    d = db()
    day = valid_date(request.values.get("day")) or today()
    if request.method == "POST":
        for m in d.execute("SELECT id FROM users WHERE role='member' AND active=1").fetchall():
            st = request.form.get(f"s{m['id']}")
            if st in ATT:
                note = clip(request.form.get(f"n{m['id']}"), 200)
                d.execute("""INSERT INTO attendance(day, user_id, status, note) VALUES(?,?,?,?)
                             ON CONFLICT(day, user_id) DO UPDATE SET status=excluded.status,
                             note=excluded.note""", (day, m["id"], st, note))
        d.commit()
        flash(f"{day} yo‘qlamasi saqlandi")
        return redirect(url_for("attendance", day=day))
    members_list = d.execute("""SELECT u.id, u.full_name, a.status, a.note FROM users u
                                LEFT JOIN attendance a ON a.user_id=u.id AND a.day=?
                                WHERE u.role='member' AND u.active=1
                                ORDER BY u.full_name""", (day,)).fetchall()
    return page(ATTEND, "Yo‘qlama", members=members_list, day=day, ATT=ATT)


# ---------- Statistika ----------

STATS = """<div class="card"><h1>Yo‘qlama statistikasi</h1>
<table><tr><th>A'zo</th><th>Keldi</th><th>Kelmadi</th><th>Sababli</th><th>Ishtirok</th></tr>
{% for r in att %}<tr><td>{{ r.name }}</td><td>{{ r.came }}</td><td>{{ r.absent }}</td>
<td>{{ r.excused }}</td><td>{{ r.pct }}%</td></tr>
{% else %}<tr><td colspan="5" class="muted">Ma‘lumot yo‘q</td></tr>{% endfor %}</table></div>
<div class="card"><h1>Topshiriq statistikasi</h1>
<table><tr><th>A'zo</th><th>Jami</th><th>Qabul qilingan</th><th>Kechikkan</th><th>Muddati o‘tgan</th></tr>
{% for r in tsk %}<tr><td>{{ r.name }}</td><td>{{ r.total }}</td><td>{{ r.accepted }}</td>
<td>{{ r.late }}</td><td>{{ r.overdue }}</td></tr>
{% else %}<tr><td colspan="5" class="muted">Ma‘lumot yo‘q</td></tr>{% endfor %}</table></div>"""


@app.route("/stats")
@login_required(admin=True)
def stats():
    d = db()
    members_list = d.execute("SELECT id, full_name FROM users WHERE role='member' ORDER BY full_name").fetchall()
    yo = {r["id"]: r for r in d.execute("""SELECT u.id,
            SUM(CASE WHEN a.status='keldi' THEN 1 ELSE 0 END) AS came,
            SUM(CASE WHEN a.status='kelmadi' THEN 1 ELSE 0 END) AS absent,
            SUM(CASE WHEN a.status='sababli' THEN 1 ELSE 0 END) AS excused,
            COUNT(a.id) AS marked
            FROM users u LEFT JOIN attendance a ON a.user_id=u.id
            WHERE u.role='member' GROUP BY u.id""").fetchall()}
    tk = {r["id"]: r for r in d.execute("""SELECT u.id,
            COUNT(t.id) AS total,
            SUM(CASE WHEN t.status='qabul' THEN 1 ELSE 0 END) AS accepted,
            SUM(CASE WHEN t.submitted_at IS NOT NULL AND t.due_date IS NOT NULL
                      AND substr(t.submitted_at,1,10) > t.due_date THEN 1 ELSE 0 END) AS late,
            SUM(CASE WHEN t.status!='qabul' AND t.due_date IS NOT NULL
                      AND t.due_date < ? THEN 1 ELSE 0 END) AS overdue
            FROM users u LEFT JOIN tasks t ON t.assignee_id=u.id
            WHERE u.role='member' GROUP BY u.id""", (today(),)).fetchall()}
    att_rows, task_rows = [], []
    for m in members_list:
        y = yo[m["id"]]
        k = tk[m["id"]]
        marked = y["marked"] or 0
        came = y["came"] or 0
        att_rows.append(dict(name=m["full_name"], came=came, absent=y["absent"] or 0,
                             excused=y["excused"] or 0,
                             pct=round(100 * came / marked) if marked else 0))
        task_rows.append(dict(name=m["full_name"], total=k["total"] or 0,
                              accepted=k["accepted"] or 0, late=k["late"] or 0,
                              overdue=k["overdue"] or 0))
    att_rows.sort(key=lambda r: -r["absent"])
    return page(STATS, "Statistika", att=att_rows, tsk=task_rows)


# ---------- Ishga tushirish ----------

# ---------- Faollik yuklamalari ----------

UPLOADS = """<div class="card"><h1>Faollik uchun yuklash</h1>
{% if not is_admin %}
<p class="muted">Tadbir, ishtirok yoki sababli kun uchun rasm yoki PDF yuklang (10 MB gacha).</p>
<form method="post" enctype="multipart/form-data">
<label>Sarlavha</label><input name="title" maxlength="200" required>
<label>Sana</label><input type="date" name="day" value="{{ today }}">
<label>Izoh</label><textarea name="note" rows="2" maxlength="500"></textarea>
<label>Fayl (JPG, PNG, GIF, WEBP yoki PDF)</label>
<input type="file" name="file" accept=".jpg,.jpeg,.png,.gif,.webp,.pdf" required>
<button>Yuklash</button></form>
{% else %}<p class="muted">Barcha a'zolarning yuklamalari. Yuklab olish yoki o‘chirish mumkin.</p>{% endif %}
</div>
<div class="card"><h1>{{ 'Barcha yuklamalar' if is_admin else 'Mening yuklamalarim' }}</h1>
<table><tr><th>Sana</th>{% if is_admin %}<th>A'zo</th>{% endif %}<th>Sarlavha</th><th>Izoh</th><th>Fayl</th><th></th></tr>
{% for r in rows %}<tr><td>{{ r.day or '—' }}</td>
{% if is_admin %}<td>{{ r.name }}</td>{% endif %}
<td>{{ r.title }}</td><td>{{ r.note or '' }}</td>
<td><a href="{{ url_for('upload_file', uid=r.id) }}">{{ r.orig }}</a></td>
<td>{% if is_admin or r.user_id == user.id %}
<form method="post" action="{{ url_for('upload_delete', uid=r.id) }}" onsubmit="return confirm('O‘chirilsinmi?')">
<button class="red">O‘chirish</button></form>{% endif %}</td></tr>
{% else %}<tr><td colspan="6" class="muted">Yuklamalar yo‘q</td></tr>{% endfor %}</table></div>"""


def file_ok(ext, head):
    if ext not in ALLOWED_EXT:
        return False
    if ext == ".webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    return head.startswith(ALLOWED_EXT[ext])


@app.route("/uploads", methods=["GET", "POST"])
@login_required()
def uploads():
    d = db()
    is_admin = g.user["role"] == "admin"
    if request.method == "POST":
        if is_admin:
            abort(403)
        f = request.files.get("file")
        title = clip(request.form.get("title"), 200)
        if not f or not f.filename or not title:
            flash("Sarlavha va fayl kiritilishi kerak")
            return redirect(url_for("uploads"))
        orig = os.path.basename(f.filename)[:MAX_FILE_NAME]
        ext = os.path.splitext(orig)[1].lower()
        head = f.stream.read(12)
        f.stream.seek(0)
        if not file_ok(ext, head):
            flash("Faqat JPG, PNG, GIF, WEBP rasm yoki PDF yuklash mumkin")
            return redirect(url_for("uploads"))
        stored = secrets.token_hex(16) + ext
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        f.save(os.path.join(UPLOAD_DIR, stored))
        d.execute("""INSERT INTO uploads(user_id, title, day, note, orig, stored, created_at)
                     VALUES(?,?,?,?,?,?,?)""",
                  (g.user["id"], title, valid_date(request.form.get("day")),
                   clip(request.form.get("note"), 500), orig, stored, now()))
        d.commit()
        flash("Fayl yuklandi")
        return redirect(url_for("uploads"))
    if is_admin:
        rows = d.execute("""SELECT x.*, u.full_name AS name FROM uploads x
                            JOIN users u ON u.id=x.user_id ORDER BY x.created_at DESC""").fetchall()
    else:
        rows = d.execute("SELECT * FROM uploads WHERE user_id=? ORDER BY created_at DESC",
                         (g.user["id"],)).fetchall()
    return page(UPLOADS, "Yuklamalar", rows=rows, is_admin=is_admin, today=today())


def _upload_or_404(uid):
    r = db().execute("SELECT * FROM uploads WHERE id=?", (uid,)).fetchone()
    if r is None:
        abort(404)
    if g.user["role"] != "admin" and r["user_id"] != g.user["id"]:
        abort(403)
    return r


@app.route("/uploads/<int:uid>/file")
@login_required()
def upload_file(uid):
    r = _upload_or_404(uid)
    return send_from_directory(UPLOAD_DIR, r["stored"], as_attachment=True,
                               download_name=r["orig"])


@app.route("/uploads/<int:uid>/delete", methods=["POST"])
@login_required()
def upload_delete(uid):
    r = _upload_or_404(uid)
    try:
        os.remove(os.path.join(UPLOAD_DIR, r["stored"]))
    except FileNotFoundError:
        pass
    d = db()
    d.execute("DELETE FROM uploads WHERE id=?", (uid,))
    d.commit()
    flash("Fayl o‘chirildi")
    return redirect(url_for("uploads"))


@app.errorhandler(413)
def too_large(_e):
    return page("<div class='card'><h1>Fayl juda katta</h1><p>Yuklash chegarasi: 10 MB.</p>"
                "<a class='btn' href='" + "/uploads" + "'>Orqaga</a></div>", "Xatolik"), 413


# ---------- Guruh chati ----------

CHAT = """<div class="card"><h1>Guruh chati</h1>
<div id="log" class="chatlog"></div>
<form id="f" class="chatform">
<textarea id="body" rows="2" maxlength="1000" placeholder="Xabar yozing..."></textarea>
<button>Yuborish</button></form>
<p class="muted">Xabarlar har 5 soniyada yangilanadi. Enter — yuborish, Shift+Enter — yangi qator.</p></div>
<script>
(function () {
  var log = document.getElementById('log'), box = document.getElementById('body');
  var me = {{ user.id }}, isAdmin = {{ 'true' if user.role == 'admin' else 'false' }};
  var csrf = '{{ csrf_token() }}', lastId = 0, shown = {};
  function fmt(t) { return t.replace('T', ' '); }
  function add(m) {
    if (shown[m.id]) return; shown[m.id] = true;
    var row = document.createElement('div'); row.style.margin = '0 0 10px';
    var head = document.createElement('div'); head.className = 'muted';
    head.textContent = m.name + ' · ' + fmt(m.created_at);
    var text = document.createElement('div'); text.style.whiteSpace = 'pre-wrap';
    text.style.background = m.user_id === me ? '#e8f0fb' : '#fff';
    text.style.padding = '8px 10px'; text.style.borderRadius = '8px';
    text.textContent = m.body;
    row.appendChild(head); row.appendChild(text);
    if (isAdmin) {
      var del = document.createElement('button'); del.className = 'red';
      del.style.fontSize = '12px'; del.style.padding = '3px 8px'; del.textContent = 'O‘chirish';
      del.onclick = function () {
        if (!confirm('Xabar o‘chirilsinmi?')) return;
        var fd = new FormData(); fd.append('csrf', csrf);
        fetch('/chat/' + m.id + '/delete', {method: 'POST', body: fd}).then(function (r) {
          if (r.ok) { row.remove(); }
        });
      };
      row.appendChild(del);
    }
    log.appendChild(row);
    if (m.id > lastId) lastId = m.id;
  }
  function load() {
    fetch('/chat/messages?after=' + lastId).then(function (r) { return r.json(); }).then(function (list) {
      var atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 40;
      list.forEach(add);
      if (list.length && (atBottom || lastId === list[list.length - 1].id)) log.scrollTop = log.scrollHeight;
    });
  }
  document.getElementById('f').addEventListener('submit', function (e) {
    e.preventDefault();
    var text = box.value.trim(); if (!text) return;
    var fd = new FormData(); fd.append('csrf', csrf); fd.append('body', text);
    fetch('/chat', {method: 'POST', body: fd}).then(function (r) {
      if (r.ok) { box.value = ''; load(); }
    });
  });
  box.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); document.getElementById('f').requestSubmit(); }
  });
  load(); setInterval(load, 5000);
})();
</script>"""


@app.route("/chat", methods=["GET", "POST"])
@login_required()
def chat():
    d = db()
    if request.method == "POST":
        body = clip(request.form.get("body"), 1000)
        if body:
            d.execute("INSERT INTO messages(user_id, body, created_at) VALUES(?,?,?)",
                      (g.user["id"], body, now()))
            d.commit()
        return ("", 204)
    return page(CHAT, "Guruh chati")


@app.route("/chat/messages")
@login_required()
def chat_messages():
    after = request.args.get("after", "0")
    after = int(after) if after.isdigit() else 0
    rows = db().execute("""SELECT m.id, m.user_id, m.body, m.created_at, u.full_name AS name
                           FROM messages m JOIN users u ON u.id=m.user_id
                           WHERE m.id > ? ORDER BY m.id DESC LIMIT 200""", (after,)).fetchall()
    # so'nggi 200 ta xabar, eski tartibda qaytariladi
    return jsonify([dict(r) for r in reversed(rows)])


@app.route("/chat/<int:mid>/delete", methods=["POST"])
@login_required(admin=True)
def chat_delete(mid):
    d = db()
    d.execute("DELETE FROM messages WHERE id=?", (mid,))
    d.commit()
    return ("", 204)


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
