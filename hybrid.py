"""Bounded fast batch-audit workflow for owner-authorized public websites."""
import os, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser
from flask import request, jsonify
from bs4 import BeautifulSoup

MAX_BATCH = min(1000,max(1,int(os.getenv("HYBRID_MAX_BATCH","200"))))
WORKERS = min(12,max(1,int(os.getenv("HYBRID_WORKERS","4"))))
DELAY = max(1.0,float(os.getenv("HYBRID_REQUEST_DELAY","2")))
LOCK = threading.Semaphore(WORKERS)

def register_hybrid(app, connect, authorized, validate, download, scan):
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS hybrid_jobs (
          id INTEGER PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          status TEXT DEFAULT 'queued', total INTEGER, processed INTEGER DEFAULT 0,
          flagged INTEGER DEFAULT 0, error TEXT);
        CREATE TABLE IF NOT EXISTS hybrid_items (
          id INTEGER PRIMARY KEY, job_id INTEGER, url TEXT, status TEXT DEFAULT 'queued',
          http_status INTEGER, links_found INTEGER DEFAULT 0, findings INTEGER DEFAULT 0,
          note TEXT, site_id INTEGER, UNIQUE(job_id,url));
        CREATE INDEX IF NOT EXISTS hybrid_job_idx ON hybrid_items(job_id);
        """)

    def check(item):
        with LOCK:
            time.sleep(DELAY)
            url = item["url"]
            try:
                url = validate(url)
                p = urlsplit(url)
                robots_url = p.scheme + "://" + p.netloc + "/robots.txt"
                robot_status, body, _ = download(robots_url)
                if robot_status != 200:
                    note = "robots.txt unavailable or restricted; skipped"
                    code, found, issues, status = robot_status,0,0,"blocked"
                else:
                    rp = RobotFileParser()
                    rp.parse(body.decode("utf-8","replace").splitlines())
                    if not rp.can_fetch("LinkAliveBot",url):
                        code,found,issues,note,status = 403,0,0,"Disallowed by robots.txt","blocked"
                    else:
                        code,html,final = download(url)
                        if code in (401,403,429):
                            found,issues,note,status = 0,0,"Blocked or rate limited","blocked"
                        elif code >= 400:
                            found,issues,note,status = 0,1,"Homepage HTTP error","flagged"
                        elif not html:
                            found,issues,note,status = 0,0,"No HTML received","checked"
                        else:
                            soup=BeautifulSoup(html,"html.parser")
                            anchors=soup.select("a[href]")
                            found = len(anchors)
                            issues=sum(1 for a in anchors if a.get("href","").strip() in ("","#"))
                            note = "Placeholder anchor detected" if issues else "Homepage passed fast checks"
                            status = "flagged" if issues else "checked"
            except Exception as exc:
                code,found,issues,note,status = None,0,0,str(exc)[:180],"error"
            with connect() as c:
                c.execute("UPDATE hybrid_items SET status=?,http_status=?,links_found=?,findings=?,note=? WHERE id=?",
                          (status,code,found,issues,note,item["id"]))
                c.execute("UPDATE hybrid_jobs SET processed=processed+1, flagged=flagged+? WHERE id=?",
                          (int(bool(issues)),item["job_id"]))

    def run(job_id):
        with connect() as c:
            c.execute("UPDATE hybrid_jobs SET status='running' WHERE id=?",(job_id,))
            items=[dict(r) for r in c.execute("SELECT id,job_id,url FROM hybrid_items WHERE job_id=?",(job_id,))]
        try:
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                list(pool.map(check,items))
            with connect() as c:
                c.execute("UPDATE hybrid_jobs SET status='complete' WHERE id=?",(job_id,))
        except Exception as exc:
            with connect() as c:
                c.execute("UPDATE hybrid_jobs SET status='failed',error=? WHERE id=?",(str(exc)[:180],job_id))

    @app.post("/api/hybrid/jobs")
    def create_hybrid_job():
        authorized()
        payload=request.get_json(silent=True) or {}
        raw=payload.get("urls")
        if not isinstance(raw,list) or not 1<=len(raw)<=MAX_BATCH:
            return jsonify(error="Provide 1 to %d URLs"%MAX_BATCH),400
        urls=[]; invalid=[]
        for item in raw:
            try:
                url=validate(item)
                if url not in urls:urls.append(url)
            except Exception as exc:
                invalid.append({"url":str(item)[:100],"error":str(exc)[:160]})
        if not urls:return jsonify(error="No accepted sites",invalid=invalid),400
        with connect() as c:
            job=c.execute("INSERT INTO hybrid_jobs(total) VALUES(?)",(len(urls),)).lastrowid
            c.executemany("INSERT INTO hybrid_items(job_id,url) VALUES(?,?)",
                          [(job,url) for url in urls])
        thread=threading.Thread(target=run,args=(job,),daemon=True)
        thread.start()
        return jsonify(job_id=job,accepted=len(urls),invalid=invalid,status="queued"),202

    @app.get("/api/hybrid/jobs/<int:job_id>")
    def get_hybrid_job(job_id):
        authorized()
        with connect() as c:
            job=c.execute("SELECT * FROM hybrid_jobs WHERE id=?",(job_id,)).fetchone()
            if not job:return jsonify(error="Not found"),404
            items=[dict(r) for r in c.execute("SELECT * FROM hybrid_items WHERE job_id=? ORDER BY id",(job_id,))]
        return jsonify(job=dict(job),items=items)

    @app.post("/api/hybrid/items/<int:item_id>/deep")
    def deep_check(item_id):
        authorized()
        with connect() as c:
            item=c.execute("SELECT * FROM hybrid_items WHERE id=?",(item_id,)).fetchone()
            if not item:return jsonify(error="Not found"),404
            c.execute("INSERT OR IGNORE INTO sites(url) VALUES(?)",(item["url"],))
            site=c.execute("SELECT id FROM sites WHERE url=?",(item["url"],)).fetchone()
            c.execute("UPDATE hybrid_items SET site_id=?,status='deep_queued' WHERE id=?",
                      (site["id"],item_id))
        threading.Thread(target=scan,args=(site["id"],),daemon=True).start()
        return jsonify(site_id=site["id"],status="deep_queued"),202
