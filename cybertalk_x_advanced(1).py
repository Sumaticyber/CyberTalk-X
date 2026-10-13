"""CyberTalk X Advanced | Python 3.10+ | Tkinter + SQLite
Optional PDF export: python -m pip install reportlab
Admin setup (PowerShell, before app launch): $env:CYBERTALK_ADMIN_USERNAMES="your_username"
Register that username to create an admin account. Existing accounts are upgraded on startup.
"""
from __future__ import annotations
import csv, hashlib, hmac, json, os, re, secrets, sqlite3, tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import ttk, messagebox, filedialog

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / 'cybertalk_x.db'
ITERATIONS, MAX_MESSAGE, LOCKOUT_MINUTES, REFRESH_MS = 600_000, 1000, 5, 5000
ADMINS = {x.strip().casefold() for x in os.getenv('CYBERTALK_ADMIN_USERNAMES','').split(',') if x.strip()}
BG, PANEL, ALT, SIDEBAR = '#0b1220', '#111c2f', '#16243a', '#0a1020'
FG, MUTED, BLUE, CYAN, GREEN, YELLOW, RED, BORDER = '#e7edf7', '#91a2bb', '#4f8cff', '#36c7d0', '#43c98b', '#f4bc4f', '#ff647c', '#273751'

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def dt(s):
    try:
        d=datetime.fromisoformat(s); return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
    except (ValueError, TypeError): return datetime.now(timezone.utc)
def norm(s): return ' '.join(s.casefold().split())
def pw_hash(password, salt): return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS).hex()

def detect(message, recent):
    score, reasons = 0, []
    if any(norm(message)==norm(r[0]) and norm(message) for r in recent):
        score += 30; reasons.append('Duplicate/repeated message (+30)')
    current=datetime.now(timezone.utc)
    if sum(dt(r[1]) >= current-timedelta(seconds=20) for r in recent) >= 4:
        score += 30; reasons.append('5 or more posts in about 20 seconds (+30)')
    urls=re.findall(r'https?://[^\s<>()]+|www\.[^\s<>()]+', message, re.I)
    if len(urls)>=3: score+=25; reasons.append('Three or more links (+25)')
    if re.search(r'(?:bit\.ly|tinyurl\.com|t\.co/|is\.gd/|cutt\.ly|rb\.gy)',message,re.I):
        score+=15; reasons.append('Known URL-shortener pattern (+15)')
    letters=[c for c in message if c.isalpha()]
    if len(letters)>=20 and sum(c.isupper() for c in letters)/len(letters)>=.75:
        score+=10; reasons.append('High uppercase-letter ratio (+10)')
    if re.search(r'(.)\1{7,}',message): score+=10; reasons.append('Long repeated-character sequence (+10)')
    if any(p in message.casefold() for p in ('verify your account','urgent action','password expired','claim your prize','login immediately','account suspended','send your password','confirm your bank')):
        score+=15; reasons.append('Potential phishing wording (+15)')
    score=min(score,100); level='HIGH' if score>=50 else 'MEDIUM' if score>=25 else 'LOW'
    return score,level,reasons or ['No configured suspicious patterns detected']

class DB:
    def __init__(self): self.init()
    def connect(self):
        c=sqlite3.connect(DB_PATH,timeout=10); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
    def init(self):
        with self.connect() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY COLLATE NOCASE,salt TEXT NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL)''')
            c.execute('''CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL,risk_score INTEGER NOT NULL DEFAULT 0,risk_level TEXT NOT NULL DEFAULT 'LOW',reasons_json TEXT NOT NULL DEFAULT '[]',FOREIGN KEY(username) REFERENCES users(username))''')
            c.execute('''CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,username TEXT NOT NULL,event_type TEXT NOT NULL,details TEXT NOT NULL,prev_hash TEXT NOT NULL,event_hash TEXT NOT NULL)''')
            c.execute('''CREATE TABLE IF NOT EXISTS auth_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,attempted_at TEXT NOT NULL,success INTEGER NOT NULL)''')
            uc={r['name'] for r in c.execute('PRAGMA table_info(users)')}
            if 'role' not in uc: c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
            mc={r['name'] for r in c.execute('PRAGMA table_info(messages)')}
            for col,typ in [('risk_score','INTEGER NOT NULL DEFAULT 0'),('risk_level',"TEXT NOT NULL DEFAULT 'LOW'"),('reasons_json',"TEXT NOT NULL DEFAULT '[]'")]:
                if col not in mc: c.execute(f'ALTER TABLE messages ADD COLUMN {col} {typ}')
            c.execute('CREATE INDEX IF NOT EXISTS idx_msg_time ON messages(created_at)'); c.execute('CREATE INDEX IF NOT EXISTS idx_msg_user ON messages(username)'); c.execute('CREATE INDEX IF NOT EXISTS idx_auth_time ON auth_attempts(username,attempted_at)')
            for name in ADMINS: c.execute("UPDATE users SET role='admin' WHERE username=? COLLATE NOCASE",(name,))
    def audit_material(self,created,user,event,details,prev):
        return json.dumps({'created_at':created,'username':user,'event_type':event,'details':details,'prev_hash':prev},sort_keys=True,separators=(',',':'),ensure_ascii=False)
    def audit(self,c,user,event,details):
        created=now(); row=c.execute('SELECT event_hash FROM audit_log ORDER BY id DESC LIMIT 1').fetchone(); prev=row['event_hash'] if row else 'GENESIS'
        digest=hashlib.sha256(self.audit_material(created,user,event,details,prev).encode()).hexdigest()
        c.execute('INSERT INTO audit_log(created_at,username,event_type,details,prev_hash,event_hash) VALUES(?,?,?,?,?,?)',(created,user,event,details,prev,digest))
    def register(self,user,password):
        user=user.strip()
        if not re.fullmatch(r'[A-Za-z0-9_]{3,24}',user): return False,'Username must be 3–24 letters, numbers or underscores.'
        if not 10<=len(password)<=256: return False,'Password must be 10–256 characters.'
        salt=secrets.token_bytes(16); digest=pw_hash(password,salt); role='admin' if user.casefold() in ADMINS else 'user'
        try:
            with self.connect() as c:
                c.execute('INSERT INTO users(username,salt,password_hash,created_at,role) VALUES(?,?,?,?,?)',(user,salt.hex(),digest,now(),role)); self.audit(c,user,'ACCOUNT_CREATED',f'role={role}')
            return True,f'Account created. Role: {role.upper()}.'
        except sqlite3.IntegrityError: return False,'That username already exists.'
    def login(self,user,password):
        user=user.strip(); cutoff=(datetime.now(timezone.utc)-timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec='seconds')
        with self.connect() as c:
            n=c.execute('SELECT COUNT(*) n FROM auth_attempts WHERE username=? COLLATE NOCASE AND success=0 AND attempted_at>=?',(user,cutoff)).fetchone()['n']
            if n>=5:
                self.audit(c,user or 'unknown','LOGIN_RATE_LIMITED',f'failed_attempts={n}'); return False,f'Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.',None
            r=c.execute('SELECT username,salt,password_hash,role FROM users WHERE username=? COLLATE NOCASE',(user,)).fetchone(); ok=False
            if r:
                try: ok=hmac.compare_digest(pw_hash(password,bytes.fromhex(r['salt'])),r['password_hash'])
                except (ValueError,TypeError): pass
            c.execute('INSERT INTO auth_attempts(username,attempted_at,success) VALUES(?,?,?)',(user or 'unknown',now(),int(ok)))
            self.audit(c,r['username'] if r else (user or 'unknown'),'LOGIN_SUCCESS' if ok else 'LOGIN_FAILURE','verified' if ok else 'invalid credentials')
            return (True,'Login successful.',r['role']) if ok else (False,'Invalid username or password.',None)
    def post(self,user,body):
        body=body.strip()
        if not body: return False,'Message cannot be empty.',0,'LOW',[]
        if len(body)>MAX_MESSAGE: return False,f'Message must be {MAX_MESSAGE} characters or fewer.',0,'LOW',[]
        if any(ord(ch)<32 and ch not in '\n\r\t' for ch in body): return False,'Unsupported control character found.',0,'LOW',[]
        with self.connect() as c:
            old=c.execute('SELECT body,created_at FROM messages WHERE username=? COLLATE NOCASE ORDER BY id DESC LIMIT 10',(user,)).fetchall()
            score,level,reasons=detect(body,[(r['body'],r['created_at']) for r in old]); created=now()
            c.execute('INSERT INTO messages(username,body,created_at,risk_score,risk_level,reasons_json) VALUES(?,?,?,?,?,?)',(user,body,created,score,level,json.dumps(reasons,ensure_ascii=False)))
            self.audit(c,user,'MESSAGE_POSTED',json.dumps({'risk_score':score,'risk_level':level},separators=(',',':')))
            if score>=25: self.audit(c,user,'SUSPICIOUS_ACTIVITY',json.dumps({'risk_score':score,'risk_level':level,'reasons':reasons},ensure_ascii=False,separators=(',',':')))
        return True,'Message posted.',score,level,reasons
    def messages(self,search='',limit=200):
        with self.connect() as c:
            if search.strip():
                t='%'+search.strip()+'%'; rows=c.execute('SELECT * FROM messages WHERE body LIKE ? OR username LIKE ? ORDER BY id DESC LIMIT ?',(t,t,limit)).fetchall()
            else: rows=c.execute('SELECT * FROM messages ORDER BY id DESC LIMIT ?',(limit,)).fetchall()
            return [dict(r) for r in rows]
    def alerts(self):
        with self.connect() as c: return [dict(r) for r in c.execute("SELECT id,created_at,username,event_type,details FROM audit_log WHERE event_type IN ('SUSPICIOUS_ACTIVITY','LOGIN_FAILURE','LOGIN_RATE_LIMITED') ORDER BY id DESC LIMIT 200")]
    def stats(self):
        with self.connect() as c:
            q=lambda sql:c.execute(sql).fetchone()['n']
            return {'users':q('SELECT COUNT(*) n FROM users'),'messages':q('SELECT COUNT(*) n FROM messages'),'suspicious':q('SELECT COUNT(*) n FROM messages WHERE risk_score>=25'),'high':q("SELECT COUNT(*) n FROM messages WHERE risk_level='HIGH'"),'failed':q('SELECT COUNT(*) n FROM auth_attempts WHERE success=0')}
    def users(self):
        with self.connect() as c: return [dict(r) for r in c.execute('SELECT username,role,created_at FROM users ORDER BY username COLLATE NOCASE')]
    def verify(self):
        with self.connect() as c: rows=c.execute('SELECT * FROM audit_log ORDER BY id').fetchall()
        prev='GENESIS'
        for r in rows:
            if r['prev_hash']!=prev: return False,f'Chain link mismatch at event ID {r["id"]}.'
            digest=hashlib.sha256(self.audit_material(r['created_at'],r['username'],r['event_type'],r['details'],r['prev_hash']).encode()).hexdigest()
            if not hmac.compare_digest(digest,r['event_hash']): return False,f'Event hash mismatch at event ID {r["id"]}.'
            prev=r['event_hash']
        return True,f'Verified {len(rows)} audit events. A database owner could still rebuild the chain.'
    def export_csv(self,path):
        rows=list(reversed(self.messages(limit=100000)))
        with open(path,'w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f); w.writerow(['ID','Username','Message','Created UTC','Risk Score','Risk Level','Reasons'])
            for r in rows:
                try: reasons='; '.join(json.loads(r['reasons_json'] or '[]'))
                except (ValueError,TypeError): reasons=''
                w.writerow([r['id'],r['username'],r['body'],r['created_at'],r['risk_score'],r['risk_level'],reasons])
        return len(rows)
    def export_pdf(self,path):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import landscape,A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
            from reportlab.lib.units import mm
        except ImportError as e: raise RuntimeError('Install PDF dependency: python -m pip install reportlab') from e
        rows=list(reversed(self.messages(limit=1000))); styles=getSampleStyleSheet()
        story=[Paragraph('CyberTalk X — Security Activity Report',styles['Title']),Paragraph('Generated UTC: '+now(),styles['Normal']),Spacer(1,5*mm)]
        data=[['ID','User','Created UTC','Score','Level','Message and reasons']]
        for r in rows:
            try: reasons='; '.join(json.loads(r['reasons_json'] or '[]'))
            except (ValueError,TypeError): reasons=''
            esc=lambda s:str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
            summary=esc(r['body'][:180])+('…' if len(r['body'])>180 else '')
            if reasons: summary+='<br/><font color="#666666">'+esc(reasons)+'</font>'
            data.append([str(r['id']),esc(r['username']),r['created_at'][:19],str(r['risk_score']),r['risk_level'],Paragraph(summary,styles['BodyText'])])
        table=Table(data,colWidths=[12*mm,24*mm,38*mm,12*mm,18*mm,155*mm],repeatRows=1)
        table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#16243a')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.35,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),7)]))
        SimpleDocTemplate(path,pagesize=landscape(A4),rightMargin=10*mm,leftMargin=10*mm,topMargin=10*mm,bottomMargin=10*mm).build(story); return len(rows)

class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.db=DB(); self.user=None; self.role='user'; self.page='Dashboard'
        self.title('CyberTalk X | Cybersecurity Discussion Board'); self.geometry('1200x760'); self.minsize(960,620); self.configure(bg=BG); self.style(); self.protocol('WM_DELETE_WINDOW',self.destroy); self.auth()
    def style(self):
        s=ttk.Style(self)
        try:s.theme_use('clam')
        except tk.TclError:pass
        s.configure('.',font=('Segoe UI',10)); s.configure('TFrame',background=BG); s.configure('TLabel',background=BG,foreground=FG)
        s.configure('TButton',padding=(10,7),background=ALT,foreground=FG,borderwidth=0); s.map('TButton',background=[('active','#233653')])
        s.configure('Accent.TButton',background=BLUE,foreground='white'); s.map('Accent.TButton',background=[('active','#3778eb')])
        s.configure('TEntry',fieldbackground=ALT,foreground=FG,insertcolor=FG,padding=7)
        s.configure('Treeview',background=PANEL,fieldbackground=PANEL,foreground=FG,rowheight=28); s.configure('Treeview.Heading',background=ALT,foreground=FG,padding=7); s.map('Treeview',background=[('selected','#254a7d')])
    def clear(self):
        for w in self.winfo_children():w.destroy()
    def auth(self):
        self.clear(); shell=tk.Frame(self,bg=BG); shell.pack(fill='both',expand=True)
        left=tk.Frame(shell,bg=SIDEBAR,width=400); left.pack(side='left',fill='y'); left.pack_propagate(False)
        tk.Label(left,text='CYBERTALK X',bg=SIDEBAR,fg=CYAN,font=('Segoe UI',25,'bold')).pack(anchor='w',padx=38,pady=(110,12))
        tk.Label(left,text='SECURITY • COMMUNITY • TRUST',bg=SIDEBAR,fg=MUTED).pack(anchor='w',padx=40)
        tk.Label(left,text='A safer place to discuss\ncybersecurity.',bg=SIDEBAR,fg=FG,font=('Segoe UI',21,'bold'),justify='left').pack(anchor='w',padx=38,pady=45)
        tk.Label(left,text='Secure password storage\nExplainable risk detection\nAudit event monitoring',bg=SIDEBAR,fg=MUTED,justify='left').pack(anchor='w',padx=40)
        form=tk.Frame(shell,bg=PANEL,padx=34,pady=30); form.place(relx=.68,rely=.5,anchor='center',width=390,height=420)
        tk.Label(form,text='Welcome back',bg=PANEL,fg=FG,font=('Segoe UI',21,'bold')).pack(anchor='w')
        tk.Label(form,text='Sign in or create your account',bg=PANEL,fg=MUTED).pack(anchor='w',pady=(4,22))
        tk.Label(form,text='Username',bg=PANEL,fg=MUTED).pack(anchor='w'); self.eu=ttk.Entry(form); self.eu.pack(fill='x',pady=(4,14))
        tk.Label(form,text='Password',bg=PANEL,fg=MUTED).pack(anchor='w'); self.ep=ttk.Entry(form,show='●'); self.ep.pack(fill='x',pady=(4,18)); self.ep.bind('<Return>',lambda e:self.login())
        ttk.Button(form,text='Sign in',style='Accent.TButton',command=self.login).pack(fill='x',pady=(0,8)); ttk.Button(form,text='Create account',command=self.register).pack(fill='x')
        tk.Label(form,text='Password: 10–256 characters',bg=PANEL,fg=MUTED).pack(anchor='w',pady=(18,0)); self.eu.focus_set()
    def register(self):
        ok,msg=self.db.register(self.eu.get(),self.ep.get())
        (messagebox.showinfo if ok else messagebox.showerror)('Registration',msg,parent=self)
    def login(self):
        if not self.eu.get().strip() or not self.ep.get(): messagebox.showwarning('Missing details','Enter username and password.',parent=self); return
        ok,msg,role=self.db.login(self.eu.get(),self.ep.get())
        if not ok: messagebox.showerror('Sign-in failed',msg,parent=self); return
        self.user=self.eu.get().strip(); self.role=role or 'user'; self.main()
    def main(self):
        self.clear(); shell=ttk.Frame(self); shell.pack(fill='both',expand=True)
        side=tk.Frame(shell,bg=SIDEBAR,width=210); side.pack(side='left',fill='y'); side.pack_propagate(False)
        tk.Label(side,text='CYBERTALK X',bg=SIDEBAR,fg=CYAN,font=('Segoe UI',16,'bold')).pack(anchor='w',padx=18,pady=(24,3)); tk.Label(side,text='SECURITY WORKSPACE',bg=SIDEBAR,fg=MUTED,font=('Segoe UI',8)).pack(anchor='w',padx=19,pady=(0,22))
        self.nav={}
        pages=['Dashboard','Discussion Board','Security Alerts']+(['Admin Panel'] if self.role=='admin' else [])
        for p in pages:
            b=tk.Button(side,text='  '+p,anchor='w',relief='flat',bg=SIDEBAR,fg=FG,activebackground=ALT,activeforeground=FG,padx=12,pady=12,command=lambda p=p:self.show(p)); b.pack(fill='x',padx=7,pady=2); self.nav[p]=b
        tk.Frame(side,bg=SIDEBAR).pack(fill='both',expand=True); tk.Label(side,text=f'{self.user}\n{self.role.upper()}',bg=SIDEBAR,fg=MUTED,justify='left').pack(anchor='w',padx=20,pady=10); ttk.Button(side,text='Log out',command=self.logout).pack(fill='x',padx=12,pady=(0,18))
        content=ttk.Frame(shell); content.pack(side='left',fill='both',expand=True); self.heading=tk.Label(content,text='Dashboard',bg=BG,fg=FG,font=('Segoe UI',22,'bold')); self.heading.pack(anchor='w',padx=25,pady=(20,12)); self.area=ttk.Frame(content); self.area.pack(fill='both',expand=True,padx=25,pady=(0,20)); self.show('Dashboard'); self.after(REFRESH_MS,self.tick)
    def show(self,page):
        if page=='Admin Panel' and self.role!='admin': messagebox.showerror('Access denied','Admin role required.',parent=self); return
        self.page=page; self.heading.configure(text=page)
        for p,b in self.nav.items():b.configure(bg=ALT if p==page else SIDEBAR)
        for w in self.area.winfo_children():w.destroy()
        if page=='Dashboard':self.dashboard()
        elif page=='Discussion Board':self.discussion()
        elif page=='Security Alerts':self.alert_page()
        elif page=='Admin Panel':self.admin_page()
    def card(self,parent,title,value,color):
        f=tk.Frame(parent,bg=PANEL,padx=15,pady=14,highlightbackground=BORDER,highlightthickness=1); tk.Label(f,text=title.upper(),bg=PANEL,fg=MUTED,font=('Segoe UI',9,'bold')).pack(anchor='w'); tk.Label(f,text=str(value),bg=PANEL,fg=color,font=('Segoe UI',23,'bold')).pack(anchor='w',pady=(6,0)); return f
    def tree(self,parent,cols,widths):
        wrap=tk.Frame(parent,bg=PANEL); tree=ttk.Treeview(wrap,columns=cols,show='headings',height=12)
        labels={'username':'Username','risk_score':'Risk','risk_level':'Level','created_at':'Created UTC','id':'ID','event_type':'Event','details':'Details','role':'Role','message':'Message'}
        for col,width in zip(cols,widths):tree.heading(col,text=labels.get(col,col.title())); tree.column(col,width=width,minwidth=55,anchor='w')
        sc=ttk.Scrollbar(wrap,orient='vertical',command=tree.yview); tree.configure(yscrollcommand=sc.set); tree.pack(side='left',fill='both',expand=True); sc.pack(side='right',fill='y')
        tree.tag_configure('HIGH',foreground=RED); tree.tag_configure('MEDIUM',foreground=YELLOW); tree.tag_configure('LOW',foreground=GREEN); return wrap,tree
    def dashboard(self):
        s=self.db.stats(); row=tk.Frame(self.area,bg=BG); row.pack(fill='x',pady=(0,14))
        for i,(t,v,c) in enumerate([('Users',s['users'],BLUE),('Messages',s['messages'],CYAN),('Suspicious',s['suspicious'],YELLOW),('High risk',s['high'],RED)]):self.card(row,t,v,c).grid(row=0,column=i,sticky='nsew',padx=(0 if i==0 else 8,0)); row.grid_columnconfigure(i,weight=1,uniform='cards')
        panel=tk.Frame(self.area,bg=PANEL,padx=14,pady=12); panel.pack(fill='both',expand=True); tk.Label(panel,text='Recent discussion activity',bg=PANEL,fg=FG,font=('Segoe UI',13,'bold')).pack(anchor='w',pady=(0,8)); wrap,self.dtree=self.tree(panel,('username','risk_score','risk_level','created_at'),(150,75,100,200)); wrap.pack(fill='both',expand=True); self.fill_dashboard()
        ttk.Button(self.area,text='Verify audit chain',command=self.verify).pack(anchor='e',pady=8)
    def fill_dashboard(self):
        if not hasattr(self,'dtree') or not self.dtree.winfo_exists():return
        self.dtree.delete(*self.dtree.get_children())
        for r in self.db.messages(limit=12):self.dtree.insert('','end',values=(r['username'],r['risk_score'],r['risk_level'],r['created_at'][:19]),tags=(r['risk_level'],))
    def discussion(self):
        bar=tk.Frame(self.area,bg=BG); bar.pack(fill='x',pady=(0,10)); tk.Label(bar,text='Search',bg=BG,fg=MUTED).pack(side='left'); self.search=ttk.Entry(bar,width=30); self.search.pack(side='left',padx=8); self.search.bind('<Return>',lambda e:self.refresh_posts()); ttk.Button(bar,text='Search',command=self.refresh_posts).pack(side='left'); ttk.Button(bar,text='Clear',command=self.clear_search).pack(side='left',padx=5)
        post=tk.Frame(self.area,bg=PANEL,padx=14,pady=12); post.pack(fill='x',pady=(0,12)); tk.Label(post,text='Start a discussion',bg=PANEL,fg=FG,font=('Segoe UI',12,'bold')).pack(anchor='w'); self.postbox=tk.Text(post,height=3,wrap='word',bg=ALT,fg=FG,insertbackground=FG,relief='flat',padx=8,pady=7); self.postbox.pack(fill='x',pady=8); bottom=tk.Frame(post,bg=PANEL); bottom.pack(fill='x'); tk.Label(bottom,text=f'Max {MAX_MESSAGE} characters • CyberSentinel checks every post',bg=PANEL,fg=MUTED).pack(side='left'); ttk.Button(bottom,text='Post message',style='Accent.TButton',command=self.post).pack(side='right')
        self.posts=tk.Frame(self.area,bg=PANEL,padx=12,pady=10); self.posts.pack(fill='both',expand=True); self.refresh_posts()
    def clear_search(self):self.search.delete(0,'end'); self.refresh_posts()
    def refresh_posts(self):
        if not hasattr(self,'posts') or not self.posts.winfo_exists():return
        for w in self.posts.winfo_children():w.destroy()
        rows=self.db.messages(self.search.get() if hasattr(self,'search') else '',100)
        canvas=tk.Canvas(self.posts,bg=PANEL,highlightthickness=0); sb=ttk.Scrollbar(self.posts,orient='vertical',command=canvas.yview); inner=tk.Frame(canvas,bg=PANEL); inner.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all'))); canvas.create_window((0,0),window=inner,anchor='nw'); canvas.configure(yscrollcommand=sb.set); canvas.pack(side='left',fill='both',expand=True); sb.pack(side='right',fill='y')
        if not rows:tk.Label(inner,text='No messages yet. Start the discussion!',bg=PANEL,fg=MUTED).pack(anchor='w',pady=10); return
        for r in rows:
            level=r['risk_level']; color=RED if level=='HIGH' else YELLOW if level=='MEDIUM' else GREEN; card=tk.Frame(inner,bg=ALT,padx=12,pady=10); card.pack(fill='x',pady=4,padx=2); head=tk.Frame(card,bg=ALT); head.pack(fill='x'); tk.Label(head,text=r['username'],bg=ALT,fg=CYAN,font=('Segoe UI',10,'bold')).pack(side='left'); tk.Label(head,text=f'{level} RISK • {r["risk_score"]}/100',bg=ALT,fg=color,font=('Segoe UI',9,'bold')).pack(side='right'); tk.Label(card,text=r['created_at'][:19]+' UTC',bg=ALT,fg=MUTED,font=('Segoe UI',8)).pack(anchor='w',pady=(3,5)); tk.Label(card,text=r['body'],bg=ALT,fg=FG,wraplength=760,justify='left',anchor='w').pack(fill='x')
            if r['risk_score']>=25:
                try: reasons='; '.join(json.loads(r['reasons_json'] or '[]'))
                except (ValueError,TypeError):reasons=''
                tk.Label(card,text='Detection: '+reasons,bg=ALT,fg=YELLOW,wraplength=760,justify='left',anchor='w').pack(fill='x',pady=(5,0))
    def post(self):
        ok,msg,score,level,reasons=self.db.post(self.user,self.postbox.get('1.0','end'))
        if not ok:messagebox.showwarning('Cannot post',msg,parent=self);return
        self.postbox.delete('1.0','end'); self.refresh_posts()
        if score>=25:messagebox.showwarning(f'CyberSentinel: {level}',f'Risk score: {score}/100\n\n'+'\n'.join('• '+x for x in reasons)+'\n\nThis rule-based warning is not proof of malicious intent.',parent=self)
        else:messagebox.showinfo('Posted','Message posted and checked.',parent=self)
    def alert_page(self):
        top=tk.Frame(self.area,bg=BG); top.pack(fill='x',pady=(0,10)); tk.Label(top,text='Suspicious activity and authentication events',bg=BG,fg=MUTED).pack(side='left'); ttk.Button(top,text='Refresh',command=lambda:self.show('Security Alerts')).pack(side='right'); wrap,tree=self.tree(self.area,('id','created_at','username','event_type','details'),(55,165,120,190,420)); wrap.pack(fill='both',expand=True)
        for r in self.db.alerts():tree.insert('','end',values=(r['id'],r['created_at'][:19],r['username'],r['event_type'],r['details'][:160]))
    def admin_page(self):
        s=self.db.stats(); cards=tk.Frame(self.area,bg=BG); cards.pack(fill='x',pady=(0,12))
        for i,(t,v,c) in enumerate([('Users',s['users'],BLUE),('Messages',s['messages'],CYAN),('Suspicious',s['suspicious'],YELLOW),('Failed logins',s['failed'],RED)]):self.card(cards,t,v,c).grid(row=0,column=i,sticky='nsew',padx=(0 if i==0 else 8,0)); cards.grid_columnconfigure(i,weight=1,uniform='admin')
        panel=tk.Frame(self.area,bg=PANEL,padx=12,pady=12); panel.pack(fill='both',expand=True); bar=tk.Frame(panel,bg=PANEL); bar.pack(fill='x',pady=(0,8)); tk.Label(bar,text='Registered users',bg=PANEL,fg=FG,font=('Segoe UI',12,'bold')).pack(side='left'); ttk.Button(bar,text='Export CSV',command=self.export_csv).pack(side='right',padx=4); ttk.Button(bar,text='Export PDF',command=self.export_pdf).pack(side='right',padx=4); ttk.Button(bar,text='Verify audit',command=self.verify).pack(side='right',padx=4)
        wrap,tree=self.tree(panel,('username','role','created_at'),(220,120,260)); wrap.pack(fill='both',expand=True)
        for r in self.db.users():tree.insert('','end',values=(r['username'],r['role'].upper(),r['created_at'][:19]))
    def export_csv(self):
        p=filedialog.asksaveasfilename(parent=self,defaultextension='.csv',filetypes=[('CSV','*.csv')],initialfile='cybertalk_x_report.csv')
        if not p:return
        try:n=self.db.export_csv(p);messagebox.showinfo('Export complete',f'Exported {n} messages to:\n{p}',parent=self)
        except (OSError,sqlite3.Error) as e:messagebox.showerror('Export failed',str(e),parent=self)
    def export_pdf(self):
        p=filedialog.asksaveasfilename(parent=self,defaultextension='.pdf',filetypes=[('PDF','*.pdf')],initialfile='cybertalk_x_report.pdf')
        if not p:return
        try:n=self.db.export_pdf(p);messagebox.showinfo('Export complete',f'Exported {n} messages to:\n{p}',parent=self)
        except (OSError,sqlite3.Error,RuntimeError) as e:messagebox.showerror('PDF export failed',str(e),parent=self)
    def verify(self):
        ok,msg=self.db.verify(); (messagebox.showinfo if ok else messagebox.showerror)('Audit verification',msg,parent=self)
    def logout(self):self.user=None;self.role='user';self.auth()
    def tick(self):
        if not self.winfo_exists():return
        if self.user and self.page=='Dashboard':self.fill_dashboard()
        elif self.user and self.page=='Discussion Board':self.refresh_posts()
        self.after(REFRESH_MS,self.tick)

if __name__=='__main__':App().mainloop()
