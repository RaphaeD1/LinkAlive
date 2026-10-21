"""Manual prospect CRM and reviewable evidence-based outreach drafts. No email sending."""
from flask import request, jsonify
from urllib.parse import urlsplit

def register_prospects(app, connect, authorized):
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS prospects (
          id INTEGER PRIMARY KEY,
          site_id INTEGER NOT NULL,
          business TEXT NOT NULL,
          email TEXT DEFAULT '',
          contact_source TEXT DEFAULT '',
          stage TEXT DEFAULT 'identified',
          notes TEXT DEFAULT '',
          opted_out INTEGER DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS prospect_site_idx ON prospects(site_id);
        """)

    @app.get("/api/prospects")
    def list_prospects():
        authorized()
        with connect() as c:
            return jsonify([dict(x) for x in c.execute("SELECT * FROM prospects ORDER BY id DESC LIMIT 500")])

    @app.post("/api/prospects")
    def add_prospect():
        authorized()
        data=request.get_json(silent=True) or {}
        business=str(data.get("business","")).strip()[:140]
        email=str(data.get("email","")).strip()[:200]
        source=str(data.get("contact_source","")).strip()[:500]
        notes=str(data.get("notes","")).strip()[:1000]
        try: site_id=int(data.get("site_id",0))
        except (TypeError, ValueError): site_id=0
        if not business or site_id<1:return jsonify(error="Business and valid site_id required"),400
        with connect() as c:
            site=c.execute("SELECT id FROM sites WHERE id=?",(site_id,)).fetchone()
            if not site:return jsonify(error="Site not found"),404
            cur=c.execute("INSERT INTO prospects(site_id,business,email,contact_source,notes) VALUES(?,?,?,?,?)",
                          (site_id,business,email,source,notes))
            return jsonify(id=cur.lastrowid,stage="identified"),201

    @app.patch("/api/prospects/<int:prospect_id>")
    def update_prospect(prospect_id):
        authorized()
        data=request.get_json(silent=True) or {}
        valid=("identified","reviewed","contacted","responded","quoted","paid","authorized","completed","closed")
        stage=data.get("stage")
        opted_out=data.get("opted_out")
        if stage is not None and stage not in valid:
            return jsonify(error="Invalid stage"),400
        if opted_out is not None and not isinstance(opted_out,bool):
            return jsonify(error="opted_out must be boolean"),400
        with connect() as c:
            row=c.execute("SELECT * FROM prospects WHERE id=?",(prospect_id,)).fetchone()
            if not row:return jsonify(error="Prospect not found"),404
            if stage is not None:c.execute("UPDATE prospects SET stage=? WHERE id=?",(stage,prospect_id))
            if opted_out is not None:c.execute("UPDATE prospects SET opted_out=? WHERE id=?",(int(opted_out),prospect_id))
        return jsonify(updated=True),200

    @app.get("/api/prospects/<int:prospect_id>/draft")
    def draft_prospect(prospect_id):
        authorized()
        with connect() as c:
            prospect=c.execute("SELECT * FROM prospects WHERE id=?",(prospect_id,)).fetchone()
            if not prospect:return jsonify(error="Prospect not found"),404
            if prospect["opted_out"]:return jsonify(error="Contact opted out"),409
            site=c.execute("SELECT * FROM sites WHERE id=?",(prospect["site_id"],)).fetchone()
            issues=[dict(r) for r in c.execute("SELECT target,code,issue FROM issues WHERE site_id=? AND code IN (404,410,500,502,503,504) LIMIT 3",
                                             (prospect["site_id"],))]
        if not site or not issues:return jsonify(error="No verified qualifying HTTP findings. Review the audit before outreach."),409
        lines=["Hello,", "",
               "I reviewed a few public links on "+site["url"]+" and noticed potential issues worth checking:"]
        for issue in issues:lines.append("- "+issue["target"]+" (HTTP "+str(issue["code"])+")")
        lines += ["", "These findings can be temporary, so please verify them independently.",
                  "If you would like help investigating or repairing the links, reply and I can provide a quote.",
                  "", "Best regards,", "[Your business name]", "[Business contact and postal address]",
                  "If you prefer no further contact, reply 'opt out'."]
        return jsonify(
            to=prospect["email"],
            subject="Possible broken links on "+(urlsplit(site["url"]).hostname or "your website"),
            body="\n".join(lines),
            send_enabled=False,
            note="Draft only. Confirm findings, recipient, identity, CAN-SPAM compliance and opt-out before manually sending."
        )
