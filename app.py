import os, re, sqlite3, socket, ipaddress, secrets, threading
from datetime import datetime, timezone
from urllib.parse import urlsplit, urljoin
from urllib.robotparser import RobotFileParser
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template_string, abort
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20000
DB = os.environ.get("DATABASE_PATH", "/tmp/linkalive.db")
TOKEN = os.environ.get("ADMIN_TOKEN", "")
UA = "LinkAliveBot/1.0 (public-link-audit)"
lock = threading.Lock()

def db():
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE, status TEXT DEFAULT 'pending', checked_at TEXT, checked INTEGER DEFAULT 0, broken INTEGER DEFAULT 0, error TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS issues (id INTEGER PRIMARY KEY, site_id INTEGER, source TEXT, target TEXT, code INTEGER, issue TEXT, checked_at TEXT)")

def authorized():
    if not TOKEN or not secrets.compare_digest(request.headers.get("X-Admin-Token", ""), TOKEN):
        abort(401)

def validate(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Invalid URL")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.port not in (None, 80, 443):
        raise ValueError("Only public HTTP(S) websites on standard ports are allowed")
    h = p.hostname.rstrip(".").lower()
    if h in ("localhost",) or h.endswith((".localhost", ".local", ".internal", ".test")):
        raise ValueError("Private hostname blocked")
    ips = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    if not ips or any(not ipaddress.ip_address(i[4][0]).is_global for i in ips):
        raise ValueError("Non-public address blocked")
    return url

def download(url, method="GET"):
    s = requests.Session()
    s.trust_env = False
    s.headers.update({"User-Agent": UA})
    for _ in range(5):
        validate(url)
        with s.request(method, url, allow_redirects=False, timeout=(3, 7), stream=True) as r:
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                url = urljoin(url, r.headers["Location"])
                if r.status_code == 303: method = "GET"
                continue
            chunks = []
            length = 0
            if method == "GET" and "text/html" in r.headers.get("content-type", "").lower():
                for ch in r.iter_content(8192):
                    length += len(ch)
                    if length > 500000: break
                    chunks.append(ch)
            return r.status_code, b"".join(chunks), url
    raise ValueError("Excessive redirects")

def scan(site_id):
    with db() as c:
        site = c.execute("SELECT url FROM sites WHERE id=?", (site_id,)).fetchone()
    if not site: return
    url = site["url"]
    stamp = datetime.now(timezone.utc).isoformat()
    issues, count, error = [], 0, ""
    try:
        validate(url)
        robots = RobotFileParser()
        base = urlsplit(url)
        robots_url = base.scheme + "://" + base.netloc + "/robots.txt"
        robot_status, robot_bytes, _ = download(robots_url)
        if robot_status != 200:
            raise ValueError("robots.txt unavailable or restricted; skipping scan")
        robots.parse(robot_bytes.decode("utf-8", "replace").splitlines())
        if not robots.can_fetch(UA, url):
            raise ValueError("robots.txt disallows scan")
        status, html, final = download(url)
        count += 1
        if status >= 400: issues.append((url, url, status, "Homepage HTTP error"))
        if status < 400 and html:
            doc = BeautifulSoup(html, "html.parser")
            urls = []
            for a in doc.select("a[href]"):
                href = a.get("href", "").strip()
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")): continue
                target = urljoin(final, href).split("#")[0]
                if target not in urls and urlsplit(target).scheme in ("http", "https"):
                    urls.append(target)
            for target in urls[:20]:
                try:
                    if not robots.can_fetch(UA, target) and urlsplit(target).netloc == base.netloc:
                        continue
                    code, _, _ = download(target, "HEAD")
                    if code in (403, 405, 429): continue
                    if code >= 400: issues.append((final, target, code, "Link HTTP error"))
                except (requests.RequestException, ValueError, OSError):
                    pass
                count += 1
    except Exception as exc:
        error = str(exc)[:250]
    with db() as c:
        c.execute("DELETE FROM issues WHERE site_id=?", (site_id,))
        c.executemany("INSERT INTO issues(site_id,source,target,code,issue,checked_at) VALUES(?,?,?,?,?,?)",
                      [(site_id, a,b,cod,msg,stamp) for a,b,cod,msg in issues])
        c.execute("UPDATE sites SET status=?,checked_at=?,checked=?,broken=?,error=? WHERE id=?",
                  ("error" if error else "complete", stamp, count,len(issues),error,site_id))

@app.get("/health")
def health(): return jsonify(status="ok")

@app.get("/")
def home():
    return render_template_string("""<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LinkAlive</title><style>body{font:16px system-ui;background:#0b1425;color:#eaf4ff;max-width:850px;margin:40px auto;padding:20px}input,button{padding:13px;border-radius:8px;border:0;margin:4px}button{background:#5de0b2;cursor:pointer}section{background:#17253b;border-radius:15px;padding:20px;margin:16px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#5de0b2}</style><h1>LinkAlive</h1><p>Website link health monitoring · Admin dashboard</p><section><input id="token" type="password" placeholder="Admin token"><input id="url" placeholder="https://example.com"><button onclick="add()">Add site</button><button onclick="load()">Refresh</button></section><main id="results"></main><script>const el=id=>document.getElementById(id);async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-Admin-Token':el('token').value},body:body?JSON.stringify(body):undefined});const x=await r.json();if(!r.ok)throw Error(x.error||x.message||r.status);return x}async function load(){try{const a=await api('/api/sites');let out='';for(const s of a){out+='<section><strong>'+escapeHtml(s.url)+'</strong> · '+s.status+' · '+s.broken+' broken / '+s.checked+' checked <button onclick="run('+s.id+')">Rescan</button><pre>'+escapeHtml(s.error||'')+'</pre></section>'}el('results').innerHTML=out||'<p>No saved websites.</p>'}catch(e){alert(e.message)}}async function add(){try{await api('/api/sites','POST',{url:el('url').value});load()}catch(e){alert(e.message)}}async function run(id){try{await api('/api/sites/'+id+'/scan','POST');load()}catch(e){alert(e.message)}}function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}</script></html>""")

@app.errorhandler(401)
def unauthorized(e): return jsonify(error="Admin token required"),401
@app.errorhandler(400)
def bad(e): return jsonify(error="Bad request"),400

@app.get("/api/sites")
def sites():
    authorized()
    with db() as c: return jsonify([dict(x) for x in c.execute("SELECT * FROM sites ORDER BY id DESC LIMIT 500")])

@app.post("/api/sites")
def add():
    authorized()
    try: url = validate((request.get_json(silent=True) or {}).get("url", ""))
    except (ValueError, OSError) as e: return jsonify(error=str(e)),400
    with db() as c:
        c.execute("INSERT OR IGNORE INTO sites(url) VALUES(?)", (url,))
        row = c.execute("SELECT id FROM sites WHERE url=?", (url,)).fetchone()
    return jsonify(id=row["id"], url=url),201

@app.post("/api/sites/<int:site_id>/scan")
def rescan(site_id):
    authorized()
    with lock: scan(site_id)
    return jsonify(status="complete",site_id=site_id)

@app.get("/api/sites/<int:site_id>/issues")
def issue_list(site_id):
    authorized()
    with db() as c:
        return jsonify([dict(x) for x in c.execute("SELECT * FROM issues WHERE site_id=? LIMIT 500",(site_id,))])

def rescan_due():
    if not TOKEN: return
    with db() as c:
        ids = [r[0] for r in c.execute("SELECT id FROM sites WHERE checked_at IS NULL OR checked_at < datetime('now','-1 day') LIMIT 20")]
    for site_id in ids:
        with lock: scan(site_id)

init()
from hybrid import register_hybrid
from prospects import register_prospects
register_hybrid(app, db, authorized, validate, download, scan)
register_prospects(app, db, authorized)
if os.getenv("ENABLE_SCHEDULER", "0") == "1":
    scheduler=BackgroundScheduler(daemon=True)
    scheduler.add_job(rescan_due,"interval",hours=1,max_instances=1,coalesce=True)
    scheduler.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT","8080")))
