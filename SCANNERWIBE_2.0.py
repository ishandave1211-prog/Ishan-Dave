# -*- coding: utf-8 -*-
"""
SCANNERWIBE_2.0 — Cyber Operations Centre
Animated topbar glow bars · Modern redesign · No errors
"""
import tkinter as tk
from tkinter import messagebox, filedialog
import threading, socket, ssl, re, json, time, datetime
import platform, ipaddress, urllib.request, urllib.error
import math, random
from collections import defaultdict
 
# ═══════════════════════════════════════════════════
#  PALETTE
# ═══════════════════════════════════════════════════
C = {
    "bg":       "#000000", "bg1":    "#0a0a0a",
    "bg2":      "#111111", "bg3":    "#181818",
    "bg4":      "#202020", "bg5":    "#2a2a2a",
    "border":   "#1c1c1c", "border2":"#282828", "border3":"#383838",
    "text":     "#f0f0f0", "text2":  "#808080", "text3":  "#404040",
    "accent":   "#ffffff", "accent2":"#b0b0b0",
    "green":    "#00ff88", "green2": "#00cc66", "green_bg":"#001408",
    "yellow":   "#ffcc00", "yellow2":"#cc9900", "yellow_bg":"#130f00",
    "red":      "#ff3333", "red2":   "#cc1111", "red_bg":  "#130000",
    "orange":   "#ff7700", "orange2":"#cc5500", "orange_bg":"#130600",
    "cyan":     "#00ccff", "cyan2":  "#0099cc", "cyan_bg": "#000f1a",
    "purple":   "#cc88ff", "purple2":"#9933ff", "purple_bg":"#0a0013",
    "teal":     "#00ffcc",
}
SEV_COL  = {"CRITICAL":C["red"],"HIGH":C["orange"],"MEDIUM":C["yellow"],
            "LOW":C["green"],"INFO":C["cyan"],"SAFE":C["teal"]}
SEV_BG   = {"CRITICAL":C["red_bg"],"HIGH":C["orange_bg"],"MEDIUM":C["yellow_bg"],
            "LOW":C["green_bg"],"INFO":C["cyan_bg"],"SAFE":C["green_bg"]}
SEV_BORD = {"CRITICAL":C["red2"],"HIGH":C["orange2"],"MEDIUM":C["yellow2"],
            "LOW":C["green2"],"INFO":C["cyan2"],"SAFE":C["green2"]}
 
# ═══════════════════════════════════════════════════
#  DATABASES
# ═══════════════════════════════════════════════════
COMMON_PORTS = {
    21:("FTP","Transmits credentials in plain text."),
    22:("SSH","Ensure key-based auth; disable root login."),
    23:("Telnet","Unencrypted — replace with SSH immediately."),
    25:("SMTP","Check relay and AUTH settings."),
    53:("DNS","Check for zone-transfer vulnerabilities."),
    80:("HTTP","Check for HTTPS redirect."),
    110:("POP3","Plaintext unless TLS enforced."),
    135:("MS-RPC","Windows RPC — common attack surface."),
    139:("NetBIOS","Legacy — disable if unused."),
    143:("IMAP","Ensure STARTTLS enforced."),
    443:("HTTPS","Check certificate and cipher suites."),
    445:("SMB","WannaCry / EternalBlue target."),
    1433:("MSSQL","Never expose publicly."),
    1521:("Oracle","Never expose publicly."),
    2375:("Docker","Unauthenticated daemon = root access."),
    2376:("Docker TLS","Verify certificates."),
    3000:("Dev Server","Should not be public in production."),
    3306:("MySQL","Never expose publicly."),
    3389:("RDP","Ransomware entry point — restrict by IP."),
    4444:("Metasploit","May indicate active compromise."),
    5432:("PostgreSQL","Never expose publicly."),
    5900:("VNC","Often unencrypted — restrict strictly."),
    6379:("Redis","No auth by default — never expose."),
    8080:("HTTP Alt","Check configuration."),
    8443:("HTTPS Alt","Verify cert and access control."),
    8888:("Jupyter","May expose code execution without auth."),
    9200:("Elasticsearch","No auth in older versions."),
    27017:("MongoDB","No auth by default — must be private."),
}
DANGEROUS = {23,21,135,139,445,1433,1521,3389,5900,4444,6379,27017,9200,2375,8888}
 
SEC_HEADERS = {
    "Strict-Transport-Security":("HSTS","Forces HTTPS.","HIGH"),
    "Content-Security-Policy":("CSP","Mitigates XSS.","HIGH"),
    "X-Frame-Options":("XFO","Prevents clickjacking.","MEDIUM"),
    "X-Content-Type-Options":("XCTO","Prevents MIME-sniffing.","MEDIUM"),
    "Referrer-Policy":("RP","Controls referrer leakage.","LOW"),
    "Permissions-Policy":("PP","Controls browser features.","LOW"),
    "X-XSS-Protection":("XSS-P","Legacy XSS filter.","INFO"),
    "Cross-Origin-Embedder-Policy":("COEP","Cross-origin embedding.","LOW"),
    "Cross-Origin-Opener-Policy":("COOP","Cross-origin window attacks.","LOW"),
    "Cross-Origin-Resource-Policy":("CORP","Cross-origin resource sharing.","LOW"),
}
HEADER_FIXES = {
    "Strict-Transport-Security":'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";',
    "Content-Security-Policy":  'add_header Content-Security-Policy "default-src \'self\'";',
    "X-Frame-Options":          'add_header X-Frame-Options "DENY";',
    "X-Content-Type-Options":   'add_header X-Content-Type-Options "nosniff";',
    "Referrer-Policy":          'add_header Referrer-Policy "strict-origin-when-cross-origin";',
    "Permissions-Policy":       'add_header Permissions-Policy "geolocation=(), camera=()";',
}
 
# ═══════════════════════════════════════════════════
#  SCAN ENGINE  (runs in thread — never touches UI)
# ═══════════════════════════════════════════════════
def resolve_host(target):
    t = re.sub(r"^https?://","",target.strip().lower()).rstrip("/")
    h = t.split(":")[0]
    try: return h, socket.gethostbyname(h)
    except socket.gaierror: return h, None
 
def scan_port(host,port,timeout=1.0):
    try:
        with socket.create_connection((host,port),timeout=timeout): return True
    except: return False
 
def grab_banner(host,port,timeout=2.0):
    try:
        with socket.create_connection((host,port),timeout=timeout) as s:
            s.settimeout(timeout)
            try: return s.recv(1024).decode("utf-8",errors="replace").strip()[:120]
            except: return None
    except: return None
 
def get_ssl_info(host,port=443,timeout=5.0):
    r={"error":None,"valid":False,"cert":{},"issues":[]}
    ctx=ssl.create_default_context()
    try:
        with socket.create_connection((host,port),timeout=timeout) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as s:
                cert=s.getpeercert(); proto=s.version(); cipher=s.cipher()
                r["valid"]=True; r["proto"]=proto
                r["cipher"]=cipher[0] if cipher else "unknown"
                subj=dict(x[0] for x in cert.get("subject",[]))
                issr=dict(x[0] for x in cert.get("issuer",[]))
                r["cert"]={"subject":subj.get("commonName","?"),
                           "issuer":issr.get("organizationName","?"),
                           "not_after":cert.get("notAfter","?")}
                try:
                    exp=datetime.datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z")
                    days=(exp-datetime.datetime.utcnow()).days
                    r["cert"]["days_left"]=days
                    if days<0: r["issues"].append(("CRITICAL","Certificate EXPIRED",days))
                    elif days<15: r["issues"].append(("HIGH",f"Cert expires in {days}d",days))
                    elif days<30: r["issues"].append(("MEDIUM",f"Cert expires in {days}d",days))
                except: pass
                if proto in ["SSLv2","SSLv3","TLSv1","TLSv1.1"]:
                    r["issues"].append(("HIGH",f"Weak protocol: {proto}",proto))
                if cipher:
                    for f in ["RC4","DES","3DES","EXPORT","NULL","ANON","MD5"]:
                        if f in cipher[0].upper():
                            r["issues"].append(("HIGH",f"Weak cipher: {cipher[0]}",cipher[0])); break
    except ssl.SSLCertVerificationError as e:
        r["error"]=str(e); r["issues"].append(("HIGH",f"Cert verify failed: {e}",""))
    except ssl.SSLError as e:
        r["error"]=str(e); r["issues"].append(("MEDIUM",f"SSL error: {e}",""))
    except: r["error"]="Port not reachable"
    return r
 
def check_http_headers(host,port=443,use_https=True,timeout=8.0):
    r={"headers":{},"issues":[],"server":None,"status":None,"error":None}
    scheme="https" if use_https else "http"
    url=f"{scheme}://{host}:{port}/" if port not in (80,443) else f"{scheme}://{host}/"
    try:
        req=urllib.request.Request(url,headers={"User-Agent":"SentinelScanner/5.0"})
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        with opener.open(req,timeout=timeout) as resp:
            r["status"]=resp.status; r["server"]=resp.headers.get("Server","")
            hl={k.lower() for k in resp.headers}
            for hdr,(abbr,desc,sev) in SEC_HEADERS.items():
                if hdr.lower() not in hl:
                    r["issues"].append({"severity":sev,"header":hdr,"abbr":abbr,
                        "message":f"Missing: {hdr}","description":desc})
            srv=resp.headers.get("Server","")
            if srv and any(x in srv for x in ["Apache/","nginx/","IIS/","PHP/"]):
                r["issues"].append({"severity":"LOW","header":"Server","abbr":"SRV",
                    "message":f"Version leak: {srv}","description":"Server header reveals version."})
            xpb=resp.headers.get("X-Powered-By","")
            if xpb:
                r["issues"].append({"severity":"LOW","header":"X-Powered-By","abbr":"XPB",
                    "message":f"Tech stack leak: {xpb}","description":"X-Powered-By reveals backend."})
    except urllib.error.HTTPError as e: r["status"]=e.code; r["error"]=f"HTTP {e.code}"
    except Exception as e: r["error"]=str(e)
    return r
 
def check_dns(host):
    r={"ip":None,"reverse":None,"issues":[]}
    try:
        ip=socket.gethostbyname(host); r["ip"]=ip
        try: r["reverse"]=socket.gethostbyaddr(ip)[0]
        except: r["reverse"]="No PTR"
        try:
            if ipaddress.ip_address(ip).is_private:
                r["issues"].append({"severity":"INFO","message":f"Private IP: {ip}",
                    "description":"Target is on an internal network."})
        except: pass
    except socket.gaierror as e:
        r["issues"].append({"severity":"HIGH","message":f"DNS failed: {e}",
            "description":"Cannot resolve hostname."})
    return r
 
def check_vulns(host,open_ports,http_result):
    findings=[]
    vuln_db=[
        (23,"VULN-001","Telnet Exposed","CRITICAL",
         "Telnet transmits all data including passwords in plain text.",
         "Connect on port 23 and capture traffic with any packet sniffer.",
         "1. Disable Telnet daemon immediately.\n2. Replace with SSH (port 22).\n3. sudo systemctl disable telnet"),
        (21,"VULN-002","FTP Service Exposed","HIGH",
         "FTP sends credentials in cleartext over the network.",
         "Passive capture with tcpdump reveals login credentials.",
         "1. Replace with SFTP or FTPS.\n2. Enforce TLS.\n3. Disable anonymous login."),
        (3389,"VULN-003","RDP Exposed","CRITICAL",
         "RDP is the top ransomware entry point. BlueKeep (CVE-2019-0708) allows pre-auth RCE.",
         "Brute-force, BlueKeep exploit, or RDP session hijacking.",
         "1. Never expose RDP to the internet.\n2. Put behind VPN.\n3. Enable NLA.\n4. Patch Windows."),
        (445,"VULN-004","SMB Publicly Accessible","CRITICAL",
         "EternalBlue (CVE-2017-0144) used by WannaCry. Unauthenticated RCE possible.",
         "EternalBlue sends crafted packets for unauthenticated code execution.",
         "1. Block port 445 at perimeter firewall.\n2. Apply MS17-010.\n3. Disable SMBv1."),
        (6379,"VULN-005","Redis Without Auth","CRITICAL",
         "Redis has no auth by default. Full data read/write access to anyone.",
         "redis-cli -h target KEYS * — no credentials needed.",
         "1. Bind to 127.0.0.1 only.\n2. Set requirepass in redis.conf.\n3. Block 6379 externally."),
        (27017,"VULN-006","MongoDB Exposed","CRITICAL",
         "MongoDB without auth led to mass data theft in 2017-2023.",
         "mongosh --host target — no password on unprotected instances.",
         "1. Enable security.authorization.\n2. Bind to 127.0.0.1.\n3. Block 27017 externally."),
        (9200,"VULN-007","Elasticsearch Exposed","HIGH",
         "Without X-Pack security all indices are readable by anyone.",
         "GET http://target:9200/_cat/indices lists all data stores.",
         "1. Enable X-Pack security.\n2. Set network.host: 127.0.0.1.\n3. Upgrade to ES 8+."),
        (2375,"VULN-008","Docker Daemon (No TLS)","CRITICAL",
         "Unauthenticated Docker API = full root access on the host.",
         "docker -H tcp://target:2375 run --privileged -v /:/host gives root shell.",
         "1. Close port 2375 immediately.\n2. Use Unix socket locally.\n3. Use TLS on 2376."),
        (8888,"VULN-009","Jupyter Notebook Exposed","HIGH",
         "Without a token anyone can run arbitrary Python on the server.",
         "Open http://target:8888/ — full Python shell if no token.",
         "1. Set strong token: jupyter notebook password.\n2. Bind to localhost.\n3. Use SSH tunnel."),
        (5900,"VULN-010","VNC Exposed","HIGH",
         "VNC is often unencrypted and brute-forceable.",
         "Direct VNC viewer connection — no encryption on standard VNC.",
         "1. Tunnel VNC over SSH.\n2. Firewall to trusted IPs.\n3. Enable VNC auth."),
        (4444,"VULN-011","Metasploit Port Open","CRITICAL",
         "Port 4444 is the default Metasploit listener — possible active compromise.",
         "System may already have a reverse shell active.",
         "1. Isolate the host immediately.\n2. Run incident response.\n3. Audit all processes."),
    ]
    for port,fid,title,sev,desc,how,fix in vuln_db:
        if port in open_ports:
            findings.append({"id":fid,"title":title,"severity":sev,
                             "description":desc,"how":how,"fix":fix,"cve":""})
    if http_result.get("issues"):
        for issue in http_result["issues"]:
            msg=issue.get("message","")
            if "Missing" in msg:
                hdr=issue["header"]
                findings.append({"id":f"HDR-{issue['abbr']}",
                    "title":f"Missing Header: {hdr}","severity":issue["severity"],
                    "description":f"Response missing {hdr}. {issue['description']}",
                    "how":f"Attacker exploits absence of {hdr} for XSS/clickjacking/MIME attacks.",
                    "fix":HEADER_FIXES.get(hdr,f"Add {hdr} header to web server config."),
                    "cve":"OWASP A05:2021"})
            elif "leak" in msg or "reveals" in msg:
                findings.append({"id":f"HDR-{issue['abbr']}","title":msg,
                    "severity":issue["severity"],"description":issue["description"],
                    "how":"Attacker fingerprints server and targets known CVEs.",
                    "fix":"nginx: server_tokens off;\nApache: ServerTokens Prod",
                    "cve":"CWE-200"})
    return findings
 
def run_scan(target, options, progress_cb, finding_cb, log_cb, done_cb):
    try:
        hostname,ip=resolve_host(target)
        log_cb(f"  Resolving {hostname}...","text3")
        all_findings=[]; open_ports=[]; http_result={}
        progress_cb(3,"DNS resolution...")
        dns=check_dns(hostname)
        for iss in dns.get("issues",[]): finding_cb(iss)
        if ip:
            log_cb(f"  Resolved  {hostname} → {ip}","accent")
            if dns.get("reverse"): log_cb(f"  Reverse   {dns['reverse']}","text3")
        else:
            log_cb("  DNS resolution failed — aborting.","red"); done_cb(all_findings); return
 
        if options.get("port_scan",True):
            ports=list(COMMON_PORTS.keys()); total=len(ports)
            log_cb(f"\n  Port scan — {total} ports","text2")
            done_count=[0]; lock=threading.Lock()
            def scan_one(port):
                is_open=scan_port(hostname,port,timeout=1.0)
                with lock:
                    done_count[0]+=1
                    progress_cb(3+int((done_count[0]/total)*38),
                                f"Scanning {done_count[0]}/{total} ports")
                    if is_open:
                        open_ports.append(port)
                        svc,_=COMMON_PORTS.get(port,("?",""))
                        col="red" if port in DANGEROUS else "green"
                        log_cb(f"    OPEN  {port:>5}/tcp  {svc}",col)
                        banner=grab_banner(hostname,port)
                        if banner: log_cb(f"          {banner[:80]}","text3")
            ts=[threading.Thread(target=scan_one,args=(p,),daemon=True) for p in ports]
            for t in ts: t.start()
            for t in ts: t.join()
            log_cb(f"\n  Found {len(open_ports)} open port(s)",
                   "green" if open_ports else "text3")
 
        if options.get("ssl",True) and (443 in open_ports or 8443 in open_ports):
            progress_cb(45,"TLS certificate analysis...")
            log_cb("\n  TLS certificate analysis","text2")
            ssl_r=get_ssl_info(hostname,443 if 443 in open_ports else 8443)
            if ssl_r.get("valid"):
                cert=ssl_r["cert"]
                log_cb(f"    Subject  {cert.get('subject','?')}","text")
                log_cb(f"    Issuer   {cert.get('issuer','?')}","text3")
                log_cb(f"    Proto    {ssl_r.get('proto','?')}","text3")
                days=cert.get("days_left")
                if days is not None:
                    log_cb(f"    Expires  {days} days","red" if days<30 else "green")
            for sev,msg,_ in ssl_r.get("issues",[]):
                f={"id":"SSL-001","title":msg,"severity":sev,
                   "description":"TLS weakness undermines encrypted comms.",
                   "how":"MITM tools intercept or tamper with encrypted traffic.",
                   "fix":"1. Renew cert.\n2. Disable TLS 1.0/1.1.\n3. Test at ssllabs.com",
                   "cve":"CWE-326"}
                all_findings.append(f); finding_cb(f)
 
        if options.get("headers",True) and (80 in open_ports or 443 in open_ports):
            progress_cb(60,"HTTP header analysis...")
            log_cb("\n  HTTP security headers","text2")
            use_https=443 in open_ports or 8443 in open_ports
            http_result=check_http_headers(hostname,443 if use_https else 80,use_https)
            if http_result.get("error") and use_https:
                http_result=check_http_headers(hostname,80,False)
            if http_result.get("status"):
                log_cb(f"    Status  HTTP {http_result['status']}","text3")
            if http_result.get("server"):
                log_cb(f"    Server  {http_result['server']}","text3")
 
        progress_cb(80,"Vulnerability correlation...")
        log_cb("\n  Vulnerability analysis","text2")
        for f in check_vulns(hostname,open_ports,http_result):
            all_findings.append(f); finding_cb(f)
 
        progress_cb(100,"Scan complete")
        crit=sum(1 for f in all_findings if f.get("severity")=="CRITICAL")
        high=sum(1 for f in all_findings if f.get("severity")=="HIGH")
        med =sum(1 for f in all_findings if f.get("severity")=="MEDIUM")
        low =sum(1 for f in all_findings if f.get("severity") in ("LOW","INFO"))
        log_cb(f"\n  ── Complete ──────────────────────────────","text3")
        log_cb(f"  {len(all_findings)} findings  Crit:{crit}  High:{high}  Med:{med}  Low:{low}","text2")
        done_cb(all_findings)
    except Exception as exc:
        log_cb(f"  Error: {exc}","red"); done_cb([])
 
# ═══════════════════════════════════════════════════
#  COLOUR HELPER
# ═══════════════════════════════════════════════════
def lerp(c1,c2,t):
    def h2r(h):
        h=h.lstrip("#")
        return tuple(int(h[i:i+2],16) for i in (0,2,4))
    r1,g1,b1=h2r(c1); r2,g2,b2=h2r(c2)
    return "#{:02x}{:02x}{:02x}".format(int(r1+(r2-r1)*t),
                                         int(g1+(g2-g1)*t),int(b1+(b2-b1)*t))
 
# ═══════════════════════════════════════════════════
#  SCROLL FRAME — trackpad + mouse wheel safe
# ═══════════════════════════════════════════════════
class ScrollFrame(tk.Frame):
    def __init__(self,parent,bg=None,**kw):
        _bg=bg or C["bg2"]
        super().__init__(parent,bg=_bg,**kw)
        self._bg=_bg
        self.canvas=tk.Canvas(self,bg=_bg,highlightthickness=0,bd=0)
        self._sb=tk.Scrollbar(self,orient="vertical",command=self.canvas.yview,
                               width=5,bg=C["bg3"],troughcolor=C["bg2"],
                               activebackground=C["bg5"],relief=tk.FLAT,bd=0)
        self.canvas.configure(yscrollcommand=self._sb.set)
        self._sb.pack(side=tk.RIGHT,fill=tk.Y)
        self.canvas.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        self.inner=tk.Frame(self.canvas,bg=_bg)
        self._win=self.canvas.create_window((0,0),window=self.inner,anchor="nw")
        self.inner.bind("<Configure>",lambda e:
            self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",lambda e:
            self.canvas.itemconfig(self._win,width=e.width))
        # scroll bindings on enter/leave to avoid grabbing scroll from other widgets
        self.canvas.bind("<Enter>",self._on_enter)
        self.canvas.bind("<Leave>",self._on_leave)
        self.inner.bind("<Enter>",self._on_enter)
        self.inner.bind("<Leave>",self._on_leave)
 
    def _on_enter(self,e=None):
        self.canvas.bind_all("<MouseWheel>",self._wheel)
        self.canvas.bind_all("<Button-4>",self._up)
        self.canvas.bind_all("<Button-5>",self._down)
 
    def _on_leave(self,e=None):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")
 
    def _wheel(self,e):
        if platform.system()=="Darwin":
            self.canvas.yview_scroll(-1*int(e.delta),"units")
        else:
            self.canvas.yview_scroll(-1*(e.delta//120),"units")
 
    def _up(self,e):   self.canvas.yview_scroll(-3,"units")
    def _down(self,e): self.canvas.yview_scroll( 3,"units")
 
    def scroll_to_top(self): self.canvas.yview_moveto(0)
 
# ═══════════════════════════════════════════════════
#  WIDGETS
# ═══════════════════════════════════════════════════
class RadarCanvas(tk.Canvas):
    def __init__(self,parent,size=160,**kw):
        super().__init__(parent,width=size,height=size,
                         bg=C["bg3"],highlightthickness=0,**kw)
        self._s=size; self._ang=0.0; self._on=False
        self._blips=[]; self._aid=None; self._redraw()
 
    def _redraw(self):
        self.delete("all")
        s=self._s; cx=cy=s//2; r=s//2-8
        for i in range(1,5):
            ri=r*i//4
            col=lerp(C["bg3"],C["green"],0.04+0.03*i)
            self.create_oval(cx-ri,cy-ri,cx+ri,cy+ri,outline=col,width=1)
        self.create_line(cx-r,cy,cx+r,cy,fill=C["border2"],width=1)
        self.create_line(cx,cy-r,cx,cy+r,fill=C["border2"],width=1)
        for bx,by,age in self._blips:
            t=max(0.0,1.0-age/20)
            col=lerp(C["bg3"],C["green"],t)
            br=max(1,int(4*t))
            self.create_oval(cx+bx-br,cy+by-br,cx+bx+br,cy+by+br,fill=col,outline="")
        if self._on:
            for i in range(0,72,3):
                ta=math.radians(self._ang-i*1.4)
                t=max(0,(72-i)/72)**2*0.5
                col=lerp(C["bg3"],C["green"],t)
                xi=cx+r*math.cos(ta); yi=cy+r*math.sin(ta)
                self.create_line(cx,cy,xi,yi,fill=col,width=1)
            a=math.radians(self._ang)
            x=cx+r*math.cos(a); y=cy+r*math.sin(a)
            self.create_line(cx,cy,x,y,fill=C["green"],width=2)
            self.create_oval(x-2,y-2,x+2,y+2,fill=C["green"],outline="")
        self.create_oval(cx-2,cy-2,cx+2,cy+2,fill=C["green2"],outline="")
 
    def start(self):
        if self._on: return
        self._on=True
        self._blips=[(random.randint(-55,55),random.randint(-55,55),random.randint(0,10))
                     for _ in range(8)]
        self._tick()
 
    def stop(self):
        self._on=False
        if self._aid: self.after_cancel(self._aid); self._aid=None
        self._redraw()
 
    def _tick(self):
        if not self._on: return
        self._ang=(self._ang+3)%360
        self._blips=[(bx,by,a+1) for bx,by,a in self._blips if a<20]
        if random.random()<0.06:
            self._blips.append((random.randint(-55,55),random.randint(-55,55),0))
        self._redraw()
        self._aid=self.after(30,self._tick)
 
 
class ArcMeter(tk.Canvas):
    def __init__(self,parent,size=130,**kw):
        super().__init__(parent,width=size,height=size,
                         bg=C["bg3"],highlightthickness=0,**kw)
        self._s=size; self._val=0.0; self._tgt=0.0; self._aid=None
        self._redraw()
 
    def _redraw(self):
        self.delete("all")
        s=self._s; cx=cy=s//2; r=s//2-12
        self.create_arc(cx-r,cy-r,cx+r,cy+r,start=225,extent=-270,
                        outline=C["border3"],width=7,style="arc")
        sc=self._val/100
        col=C["green"] if sc<0.33 else C["yellow"] if sc<0.66 else C["red"]
        ext=int(-270*sc)
        if ext: self.create_arc(cx-r,cy-r,cx+r,cy+r,start=225,extent=ext,
                                outline=col,width=7,style="arc")
        self.create_text(cx,cy-4,text=str(int(self._val)),
                         font=("Consolas",20,"bold"),fill=col)
        self.create_text(cx,cy+12,text="RISK",font=("Consolas",7),fill=C["text3"])
        lv="LOW" if sc<0.33 else "MED" if sc<0.66 else "HIGH"
        self.create_text(cx,cy+22,text=lv,font=("Consolas",8,"bold"),fill=col)
 
    def set_val(self,v):
        self._tgt=max(0,min(100,v)); self._anim()
 
    def _anim(self):
        if abs(self._val-self._tgt)<0.5:
            self._val=self._tgt; self._redraw(); return
        self._val+=(self._tgt-self._val)*0.12
        self._redraw(); self._aid=self.after(16,self._anim)
 
 
class ProgressBar(tk.Canvas):
    def __init__(self,parent,h=2,**kw):
        super().__init__(parent,height=h,bg=C["bg2"],highlightthickness=0,**kw)
        self._v=0.0; self._t=0.0; self._sh=0.0
        self.bind("<Configure>",self._draw)
 
    def _draw(self,e=None):
        w=self.winfo_width(); h=self.winfo_height()
        if w<2: return
        self.delete("all")
        self.create_rectangle(0,0,w,h,fill=C["bg4"],outline="")
        bw=int(w*self._v/100)
        if bw>0:
            self.create_rectangle(0,0,bw,h,fill=C["accent2"],outline="")
            if bw>50:
                sx=int(bw*self._sh); sw=min(80,bw//3)
                x1=max(0,sx-sw); x2=min(bw,sx+sw)
                if x2>x1: self.create_rectangle(x1,0,x2,h,fill=C["accent"],outline="")
 
    def set(self,v):
        self._t=max(0,min(100,v)); self._anim()
 
    def _anim(self):
        if abs(self._v-self._t)<0.3:
            self._v=self._t; self._draw(); return
        self._v+=(self._t-self._v)*0.14
        self._sh=(self._sh+0.022)%1.0
        self._draw(); self.after(14,self._anim)
 
 
class MiniBar(tk.Canvas):
    def __init__(self,parent,color,**kw):
        super().__init__(parent,height=2,bg=C["bg4"],highlightthickness=0,**kw)
        self._c=color; self._v=0.0; self._t=0.0
        self.bind("<Configure>",self._draw)
 
    def _draw(self,e=None):
        w=self.winfo_width()
        self.delete("all")
        self.create_rectangle(0,0,w,2,fill=C["bg5"],outline="")
        bw=int(w*self._v/100)
        if bw>0: self.create_rectangle(0,0,bw,2,fill=self._c,outline="")
 
    def set(self,pct):
        self._t=max(0,min(100,pct)); self._anim()
 
    def _anim(self):
        if abs(self._v-self._t)<0.3:
            self._v=self._t; self._draw(); return
        self._v+=(self._t-self._v)*0.15
        self._draw(); self.after(14,self._anim)
 
 
class PulseDot(tk.Label):
    def __init__(self,parent,**kw):
        super().__init__(parent,text="●",**kw)
        self._on=False; self._ph=0.0; self._col=kw.get("fg",C["green"])
 
    def start(self,col=None):
        if col: self._col=col
        self._on=True; self._tick()
 
    def stop(self,col=None):
        self._on=False
        self.config(fg=col or C["text3"])
 
    def _tick(self):
        if not self._on: return
        self._ph=(self._ph+0.15)%(2*math.pi)
        t=0.3+0.7*abs(math.sin(self._ph))
        self.config(fg=lerp(C["bg2"],self._col,t))
        self.after(40,self._tick)
 
 
class FindingCard(tk.Frame):
    def __init__(self,parent,finding,**kw):
        sev=finding.get("severity","INFO")
        col=SEV_COL.get(sev,C["cyan"])
        bg=SEV_BG.get(sev,C["bg3"])
        bdr=SEV_BORD.get(sev,C["border2"])
        super().__init__(parent,bg=C["bg2"],
                         highlightthickness=1,highlightbackground=bdr,**kw)
        self._exp=False
        # colour strip
        tk.Frame(self,bg=col,width=3).pack(side=tk.LEFT,fill=tk.Y)
        main=tk.Frame(self,bg=bg,cursor="hand2"); main.pack(fill=tk.BOTH,expand=True)
        # header
        hdr=tk.Frame(main,bg=bg); hdr.pack(fill=tk.X,padx=10,pady=7)
        pf=tk.Frame(hdr,bg=col,padx=6,pady=1); pf.pack(side=tk.LEFT,padx=(0,7))
        tk.Label(pf,text=sev,font=("Consolas",7,"bold"),fg=C["bg"],bg=col).pack()
        idf=tk.Frame(hdr,bg=C["bg3"],padx=5,pady=1); idf.pack(side=tk.LEFT,padx=(0,7))
        tk.Label(idf,text=finding.get("id","—"),font=("Consolas",7),fg=C["text3"],bg=C["bg3"]).pack()
        tl=tk.Label(hdr,text=finding.get("title",""),font=("Consolas",9,"bold"),
                    fg=C["text"],bg=bg,anchor="w")
        tl.pack(side=tk.LEFT,fill=tk.X,expand=True)
        self._chev=tk.Label(hdr,text="›",font=("Consolas",13),fg=C["text3"],bg=bg)
        self._chev.pack(side=tk.RIGHT,padx=4)
        # body
        self._body=tk.Frame(self,bg=C["bg1"])
        tk.Frame(self._body,bg=bdr,height=1).pack(fill=tk.X)
        bi=tk.Frame(self._body,bg=C["bg1"]); bi.pack(fill=tk.X,padx=12,pady=8)
        for lbl,key,ac in [("WHAT","description",C["text2"]),
                            ("HOW","how",C["yellow"]),
                            ("FIX","fix",C["green"]),
                            ("REF","cve",C["cyan"])]:
            val=finding.get(key,"")
            if not val: continue
            row=tk.Frame(bi,bg=C["bg1"]); row.pack(fill=tk.X,pady=(5,0))
            tk.Frame(row,bg=ac,width=2).pack(side=tk.LEFT,fill=tk.Y,padx=(0,7))
            inn=tk.Frame(row,bg=C["bg1"]); inn.pack(side=tk.LEFT,fill=tk.X,expand=True)
            tk.Label(inn,text=lbl,font=("Consolas",7,"bold"),fg=ac,bg=C["bg1"],anchor="w").pack(fill=tk.X)
            tk.Label(inn,text=val,font=("Consolas",8),fg=C["text2"],bg=C["bg1"],
                     anchor="w",justify=tk.LEFT,wraplength=500).pack(fill=tk.X)
        # toggle bindings on header items
        for w in [main,hdr,tl,self._chev,pf,idf]:
            w.bind("<Button-1>",self._toggle)
 
    def _toggle(self,e=None):
        if self._exp:
            self._body.pack_forget(); self._chev.config(text="›")
        else:
            self._body.pack(fill=tk.X); self._chev.config(text="⌄")
        self._exp=not self._exp
 
# ═══════════════════════════════════════════════════
#  FLOATING BARS ANIMATION  — live background widget
# ═══════════════════════════════════════════════════
class FloatingBars(tk.Canvas):
    """Animated vertical bars that float/pulse in the background."""
    BAR_DEFS = [
        # (color, x_frac, base_h_frac, speed, phase_offset)
        (C["cyan"],    0.06, 0.28, 1.8, 0.0),
        (C["green"],   0.13, 0.42, 2.2, 0.7),
        (C["purple"],  0.20, 0.35, 1.5, 1.4),
        (C["cyan"],    0.28, 0.55, 2.6, 2.1),
        (C["yellow"],  0.35, 0.30, 1.9, 0.4),
        (C["green"],   0.43, 0.48, 2.4, 1.1),
        (C["red"],     0.50, 0.22, 1.6, 2.8),
        (C["cyan"],    0.57, 0.60, 2.9, 0.9),
        (C["purple"],  0.64, 0.38, 2.0, 1.7),
        (C["green"],   0.71, 0.45, 2.3, 0.3),
        (C["yellow"],  0.78, 0.32, 1.7, 2.2),
        (C["cyan"],    0.85, 0.52, 2.5, 1.3),
        (C["green"],   0.92, 0.40, 2.1, 0.6),
    ]
 
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg1"], highlightthickness=0, **kw)
        self._phase = 0.0
        self._running = False
        self._aid = None
        self.bind("<Configure>", self._redraw)
 
    def _redraw(self, e=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        bar_w = max(6, w // 55)
        for col, xf, base_hf, spd, ph in self.BAR_DEFS:
            # animate height with sine
            t = math.sin(self._phase * spd + ph)
            hf = base_hf + 0.14 * t
            bh = int(h * hf)
            bx = int(w * xf)
            # fade top
            alpha = 0.18 + 0.10 * abs(math.sin(self._phase * spd * 0.5 + ph))
            bar_col = lerp(C["bg1"], col, alpha)
            # draw bar centered vertically in bottom 60%
            by = h - bh
            self.create_rectangle(bx, by, bx + bar_w, h,
                                  fill=bar_col, outline="")
            # glowing top cap
            cap_col = lerp(C["bg1"], col, min(1.0, alpha * 3.5))
            self.create_rectangle(bx, by, bx + bar_w, by + 3,
                                  fill=cap_col, outline="")
 
    def start(self):
        if self._running:
            return
        self._running = True
        self._animate()
 
    def stop(self):
        self._running = False
        if self._aid:
            self.after_cancel(self._aid)
            self._aid = None
 
    def _animate(self):
        if not self._running:
            return
        self._phase += 0.025
        self._redraw()
        self._aid = self.after(40, self._animate)
 
 
# ═══════════════════════════════════════════════════
#  TOPBAR GLOW BARS — mini animated bars beside logo
# ═══════════════════════════════════════════════════
class TopbarGlowBars(tk.Canvas):
    """
    Small animated equaliser-style bars that sit in the topbar
    beside the SCANNERWIBE_2.0 logo. Always running.
    """
    # Each bar: (color_key, base_height_frac, speed, phase)
    _BARS = [
        ("cyan",   0.45, 3.1, 0.00),
        ("green",  0.65, 2.4, 0.55),
        ("cyan",   0.50, 3.8, 1.10),
        ("purple", 0.70, 2.9, 1.65),
        ("cyan",   0.40, 3.4, 0.30),
        ("green",  0.80, 2.6, 2.20),
        ("yellow", 0.35, 4.0, 0.85),
        ("cyan",   0.60, 3.2, 1.40),
        ("green",  0.50, 2.7, 2.75),
        ("purple", 0.45, 3.6, 0.70),
        ("cyan",   0.75, 2.5, 1.95),
        ("green",  0.40, 3.9, 0.15),
        ("yellow", 0.65, 2.8, 2.50),
        ("cyan",   0.55, 3.3, 1.25),
        ("green",  0.70, 2.3, 0.60),
        ("purple", 0.45, 3.7, 1.80),
        ("cyan",   0.60, 2.6, 0.40),
        ("green",  0.50, 4.1, 2.10),
    ]
    BAR_W  = 3   # px wide each bar
    GAP    = 2   # px gap between bars
 
    def __init__(self, parent, **kw):
        # compute fixed width from bar count
        n = len(self._BARS)
        w = n * (self.BAR_W + self.GAP) - self.GAP
        h = kw.pop("height", 32)
        super().__init__(parent, width=w, height=h,
                         bg=C["bg2"], highlightthickness=0, **kw)
        self._h    = h
        self._ph   = 0.0
        self._aid  = None
        self._run  = False
        # pre-resolve colors once
        self._cols = [C[ck] for ck, *_ in self._BARS]
        self._start_auto()
 
    def _start_auto(self):
        """Always running — starts immediately."""
        self._run = True
        self._tick()
 
    def stop(self):
        self._run = False
        if self._aid:
            self.after_cancel(self._aid)
            self._aid = None
 
    def _tick(self):
        if not self._run:
            return
        self._ph += 0.06
        self._draw()
        self._aid = self.after(35, self._tick)
 
    def _draw(self):
        self.delete("all")
        h = self._h
        x = 0
        for i, (_, base_hf, spd, ph) in enumerate(self._BARS):
            col = self._cols[i]
            # height pulses between base*0.25 and base*1.0
            raw   = 0.5 + 0.5 * math.sin(self._ph * spd + ph)
            bar_h = max(3, int(h * base_hf * (0.25 + 0.75 * raw)))
            by    = h - bar_h
 
            # dim body
            body_col = lerp(C["bg2"], col, 0.30 + 0.20 * raw)
            self.create_rectangle(x, by, x + self.BAR_W, h,
                                  fill=body_col, outline="")
 
            # bright top cap (2 px)
            cap_col = lerp(C["bg2"], col, 0.85 + 0.15 * raw)
            self.create_rectangle(x, by, x + self.BAR_W, by + 2,
                                  fill=cap_col, outline="")
 
            x += self.BAR_W + self.GAP
 
 
# ═══════════════════════════════════════════════════
#  DASHBOARD PANEL  — rich animated home screen
# ═══════════════════════════════════════════════════
class DashboardPanel(tk.Frame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, bg=C["bg1"], **kw)
        self._app = app
        self._clock_aid = None
        self._stat_vars = {}
        self._build()
 
    def _build(self):
        # ── top bar
        tb = tk.Frame(self, bg=C["bg2"])
        tb.pack(fill=tk.X)
        lf = tk.Frame(tb, bg=C["bg2"], padx=14, pady=10)
        lf.pack(side=tk.LEFT)
        tk.Label(lf, text="⬡", font=("Consolas", 14), fg=C["accent"],
                 bg=C["bg2"]).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(lf, text="OPERATIONS CENTRE", font=("Consolas", 10, "bold"),
                 fg=C["text"], bg=C["bg2"]).pack(side=tk.LEFT)
        rf = tk.Frame(tb, bg=C["bg2"], padx=14, pady=10)
        rf.pack(side=tk.RIGHT)
        self._clk = tk.StringVar()
        tk.Label(rf, textvariable=self._clk, font=("Consolas", 8),
                 fg=C["text3"], bg=C["bg2"]).pack()
        self._tick_clock()
        tk.Frame(self, bg=C["border2"], height=1).pack(fill=tk.X)
 
        # ── scroll frame for all content
        sf = ScrollFrame(self, bg=C["bg1"])
        sf.pack(fill=tk.BOTH, expand=True)
        body = sf.inner
 
        # ══════════════════════════════════════════
        # HERO SECTION — floating bars + title stacked
        # ══════════════════════════════════════════
        hero = tk.Frame(body, bg=C["bg1"])
        hero.pack(fill=tk.X, padx=12, pady=(12, 0))
 
        # Floating bars sit in the hero, title row below it — no place() needed
        self._bars = FloatingBars(hero, height=120)
        self._bars.pack(fill=tk.X)
 
        # Title row is a normal frame BELOW the bars (clean, no z-order tricks)
        title_row = tk.Frame(hero, bg=C["bg2"])
        title_row.pack(fill=tk.X)
 
        # left: big title text
        tl = tk.Frame(title_row, bg=C["bg2"])
        tl.pack(side=tk.LEFT, padx=20, pady=14)
        tk.Label(tl, text="SCANNERWIBE_2.0", font=("Consolas", 24, "bold"),
                 fg=C["text"], bg=C["bg2"]).pack(anchor="w")
        tk.Label(tl, text="Cyber Security Operations Centre",
                 font=("Consolas", 10), fg=C["cyan"], bg=C["bg2"]).pack(anchor="w")
        tk.Label(tl, text="Port Scanner  \u00b7  SSL/TLS  \u00b7  HTTP Headers  \u00b7  Vulnerability Correlation",
                 font=("Consolas", 8), fg=C["text3"], bg=C["bg2"]).pack(anchor="w", pady=(3, 0))
 
        # right: quick stat badges
        badges = tk.Frame(title_row, bg=C["bg2"])
        badges.pack(side=tk.RIGHT, padx=20, pady=14)
        for txt, col in [("27 PORTS", C["green"]), ("10 HEADERS", C["cyan"]),
                         ("11 VULNS", C["orange"]), ("FREE", C["yellow"])]:
            bf = tk.Frame(badges, bg=C["bg3"], padx=10, pady=5,
                          highlightthickness=1, highlightbackground=col)
            bf.pack(side=tk.LEFT, padx=4)
            tk.Label(bf, text=txt, font=("Consolas", 8, "bold"),
                     fg=col, bg=C["bg3"]).pack()
 
        # ══════════════════════════════════════════
        # NAV SHORTCUT BARS — coloured clickable panels
        # ══════════════════════════════════════════
        nav_label = tk.Frame(body, bg=C["bg1"])
        nav_label.pack(fill=tk.X, padx=12, pady=(14, 4))
        tk.Label(nav_label, text="QUICK ACCESS", font=("Consolas", 7, "bold"),
                 fg=C["text3"], bg=C["bg1"]).pack(side=tk.LEFT)
        tk.Frame(nav_label, bg=C["border2"], height=1).pack(
            side=tk.LEFT, fill=tk.Y, expand=True, padx=(8, 0), pady=5)
 
        nav_row = tk.Frame(body, bg=C["bg1"])
        nav_row.pack(fill=tk.X, padx=12, pady=(0, 12))
 
        nav_items = [
            ("scanner",   "◎", "SCANNER",    "Scan any host for\nopen ports & vulns",   C["cyan"]),
            ("portref",   "⊞", "PORT REF",   "Browse 27 well-known\nport definitions",   C["green"]),
            ("headerref", "≡", "HEADERS",    "10 HTTP security\nheader reference",        C["purple"]),
            ("history",   "◷", "HISTORY",    "View past scan\nresults & timings",         C["yellow"]),
            ("about",     "?", "ABOUT",      "Usage guide &\nlegal information",           C["orange"]),
        ]
        for i, (key, icon, title, desc, col) in enumerate(nav_items):
            self._nav_bar(nav_row, key, icon, title, desc, col)
 
        # ══════════════════════════════════════════
        # LIVE STATS ROW  — radar + arc + grid
        # ══════════════════════════════════════════
        stats_label = tk.Frame(body, bg=C["bg1"])
        stats_label.pack(fill=tk.X, padx=12, pady=(4, 4))
        tk.Label(stats_label, text="LIVE SCAN METRICS", font=("Consolas", 7, "bold"),
                 fg=C["text3"], bg=C["bg1"]).pack(side=tk.LEFT)
        tk.Frame(stats_label, bg=C["border2"], height=1).pack(
            side=tk.LEFT, fill=tk.Y, expand=True, padx=(8, 0), pady=5)
 
        rowA = tk.Frame(body, bg=C["bg1"])
        rowA.pack(fill=tk.X, padx=12, pady=(0, 8))
 
        rc = self._card(rowA, "RADAR", w=178)
        rc.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        self.radar = RadarCanvas(rc, size=150)
        self.radar.pack(padx=12, pady=12)
 
        ac = self._card(rowA, "THREAT", w=148)
        ac.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        self.meter = ArcMeter(ac, size=130)
        self.meter.pack(padx=10, pady=12)
 
        sc2 = self._card(rowA, "SCAN SUMMARY")
        sc2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_stat_grid(sc2)
 
        # ══════════════════════════════════════════
        # RECENT FINDINGS
        # ══════════════════════════════════════════
        rf_label = tk.Frame(body, bg=C["bg1"])
        rf_label.pack(fill=tk.X, padx=12, pady=(4, 4))
        tk.Label(rf_label, text="RECENT FINDINGS", font=("Consolas", 7, "bold"),
                 fg=C["text3"], bg=C["bg1"]).pack(side=tk.LEFT)
        tk.Frame(rf_label, bg=C["border2"], height=1).pack(
            side=tk.LEFT, fill=tk.Y, expand=True, padx=(8, 0), pady=5)
 
        rowB = tk.Frame(body, bg=C["bg1"])
        rowB.pack(fill=tk.X, padx=12, pady=(0, 8))
        fc = self._card(rowB, "")
        fc.pack(fill=tk.X)
        self._findings_box = tk.Frame(fc, bg=C["bg2"])
        self._findings_box.pack(fill=tk.X, padx=6, pady=6)
        self._no_scan_lbl = tk.Label(
            self._findings_box,
            text="  No scan results yet — run a scan from the Scanner tab",
            font=("Consolas", 9), fg=C["text3"], bg=C["bg2"], pady=14)
        self._no_scan_lbl.pack(fill=tk.X)
 
        # ══════════════════════════════════════════
        # HOW TO USE  +  WHY USEFUL — two columns
        # ══════════════════════════════════════════
        info_label = tk.Frame(body, bg=C["bg1"])
        info_label.pack(fill=tk.X, padx=12, pady=(4, 4))
        tk.Label(info_label, text="GUIDE & IMPORTANCE", font=("Consolas", 7, "bold"),
                 fg=C["text3"], bg=C["bg1"]).pack(side=tk.LEFT)
        tk.Frame(info_label, bg=C["border2"], height=1).pack(
            side=tk.LEFT, fill=tk.Y, expand=True, padx=(8, 0), pady=5)
 
        rowD = tk.Frame(body, bg=C["bg1"])
        rowD.pack(fill=tk.X, padx=12, pady=(0, 8))
        self._build_how_to_use(rowD)
        self._build_why_useful(rowD)
 
        # ══════════════════════════════════════════
        # SEVERITY GUIDE  +  SYSTEM STATUS
        # ══════════════════════════════════════════
        rowC = tk.Frame(body, bg=C["bg1"])
        rowC.pack(fill=tk.X, padx=12, pady=(0, 16))
 
        svc = self._card(rowC, "SEVERITY GUIDE")
        svc.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self._build_sev_guide(svc)
 
        ssc = self._card(rowC, "SYSTEM STATUS")
        ssc.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._build_sys_status(ssc)
 
    # ── nav bar helper ─────────────────────────────
    def _nav_bar(self, parent, key, icon, title, desc, col):
        """One clickable coloured nav bar card."""
        outer = tk.Frame(parent, bg=col, padx=1, pady=1, cursor="hand2")
        outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
 
        inner = tk.Frame(outer, bg=C["bg2"])
        inner.pack(fill=tk.BOTH, expand=True)
 
        # top accent strip
        accent_strip = tk.Frame(inner, bg=col, height=3)
        accent_strip.pack(fill=tk.X)
 
        body = tk.Frame(inner, bg=C["bg2"], padx=12, pady=10)
        body.pack(fill=tk.BOTH, expand=True)
 
        icon_lbl = tk.Label(body, text=icon, font=("Consolas", 18),
                            fg=col, bg=C["bg2"])
        icon_lbl.pack(anchor="w")
        title_lbl = tk.Label(body, text=title, font=("Consolas", 9, "bold"),
                             fg=C["text"], bg=C["bg2"])
        title_lbl.pack(anchor="w", pady=(4, 0))
        desc_lbl = tk.Label(body, text=desc, font=("Consolas", 7),
                            fg=C["text3"], bg=C["bg2"], justify=tk.LEFT)
        desc_lbl.pack(anchor="w")
 
        # all widgets that need bg swapped on hover — stored explicitly
        hover_widgets = [inner, body, icon_lbl, title_lbl, desc_lbl]
 
        def _enter(e):
            for w in hover_widgets:
                w.config(bg=C["bg3"])
        def _leave(e):
            for w in hover_widgets:
                w.config(bg=C["bg2"])
        def _click(e):
            self._app._show(key)
 
        for w in [outer, inner, body, icon_lbl, title_lbl, desc_lbl, accent_strip]:
            w.bind("<Enter>", _enter)
            w.bind("<Leave>", _leave)
            w.bind("<Button-1>", _click)
 
    # ── how to use ─────────────────────────────────
    def _build_how_to_use(self, parent):
        card = tk.Frame(parent, bg=C["border"], padx=1, pady=1)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        inner = tk.Frame(card, bg=C["bg2"]); inner.pack(fill=tk.BOTH, expand=True)
        hdr = tk.Frame(inner, bg=C["bg3"], pady=6); hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["cyan"], width=3).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(hdr, text="  HOW TO USE SCANNERWIBE_2.0",
                 font=("Consolas", 8, "bold"), fg=C["cyan"], bg=C["bg3"]).pack(side=tk.LEFT)
 
        steps = [
            ("1", "ENTER TARGET",
             "Type a hostname or IP address (e.g. scanme.nmap.org) "
             "into the target field in the Scanner tab.",
             C["cyan"]),
            ("2", "SELECT MODULES",
             "Enable or disable Port Scan, SSL/TLS check, and HTTP Headers "
             "using the checkboxes. All three are on by default.",
             C["green"]),
            ("3", "RUN SCAN",
             "Click ▶ SCAN or press Enter. The live log shows real-time "
             "progress. All 27 ports are scanned in parallel.",
             C["yellow"]),
            ("4", "REVIEW FINDINGS",
             "Click any finding card to expand it — see what the issue is, "
             "how attackers exploit it, and the exact fix command.",
             C["orange"]),
            ("5", "EXPORT REPORT",
             "When complete, click ↓ Export to save all findings as a "
             "JSON report for sharing or ticketing.",
             C["purple"]),
        ]
 
        body = tk.Frame(inner, bg=C["bg2"]); body.pack(fill=tk.X, padx=10, pady=8)
        for num, title, text, col in steps:
            row = tk.Frame(body, bg=C["bg3"], padx=10, pady=7)
            row.pack(fill=tk.X, pady=3)
            # Number bubble
            nb = tk.Frame(row, bg=col, padx=7, pady=2)
            nb.pack(side=tk.LEFT, padx=(0, 10))
            tk.Label(nb, text=num, font=("Consolas", 9, "bold"),
                     fg=C["bg"], bg=col).pack()
            # Text
            tx = tk.Frame(row, bg=C["bg3"]); tx.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(tx, text=title, font=("Consolas", 8, "bold"),
                     fg=col, bg=C["bg3"], anchor="w").pack(fill=tk.X)
            tk.Label(tx, text=text, font=("Consolas", 7), fg=C["text2"],
                     bg=C["bg3"], anchor="w", justify=tk.LEFT,
                     wraplength=320).pack(fill=tk.X)
 
    # ── why useful ─────────────────────────────────
    def _build_why_useful(self, parent):
        card = tk.Frame(parent, bg=C["border"], padx=1, pady=1)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        inner = tk.Frame(card, bg=C["bg2"]); inner.pack(fill=tk.BOTH, expand=True)
        hdr = tk.Frame(inner, bg=C["bg3"], pady=6); hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["green"], width=3).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(hdr, text="  WHY SCANNERWIBE_2.0 MATTERS",
                 font=("Consolas", 8, "bold"), fg=C["green"], bg=C["bg3"]).pack(side=tk.LEFT)
 
        reasons = [
            ("ZERO DEPENDENCIES",
             "Runs entirely on Python's standard library. No pip install, "
             "no virtual environments, no internet access needed to run the tool.",
             C["cyan"]),
            ("INSTANT RISK VISIBILITY",
             "One scan reveals open dangerous ports, expiring certificates, "
             "missing security headers, and known CVE-linked services in under 60 seconds.",
             C["green"]),
            ("ACTIONABLE FIXES",
             "Every finding includes the exact nginx/Apache/systemctl command to fix it — "
             "not just a vague warning. Copy-paste remediation.",
             C["yellow"]),
            ("ATTACK SURFACE MAPPING",
             "Identifies services attackers target first: RDP (ransomware), "
             "Redis/MongoDB (data theft), SMB (EternalBlue/WannaCry), Docker (root escalation).",
             C["orange"]),
            ("EDUCATIONAL TOOL",
             "The Port Reference and Header Reference panels are searchable databases "
             "explaining every service and security header with severity context.",
             C["purple"]),
            ("EXPORTABLE REPORTS",
             "JSON export allows findings to be imported into ticketing systems "
             "like Jira, or shared with development teams for immediate action.",
             C["red"]),
        ]
 
        body = tk.Frame(inner, bg=C["bg2"]); body.pack(fill=tk.X, padx=10, pady=8)
        for title, text, col in reasons:
            row = tk.Frame(body, bg=C["bg3"], padx=10, pady=6)
            row.pack(fill=tk.X, pady=3)
            tk.Frame(row, bg=col, width=3).pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
            tx = tk.Frame(row, bg=C["bg3"]); tx.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(tx, text=title, font=("Consolas", 8, "bold"),
                     fg=col, bg=C["bg3"], anchor="w").pack(fill=tk.X)
            tk.Label(tx, text=text, font=("Consolas", 7), fg=C["text2"],
                     bg=C["bg3"], anchor="w", justify=tk.LEFT,
                     wraplength=320).pack(fill=tk.X)
 
    # ── card helper ────────────────────────────────
    def _card(self, parent, title, w=None):
        kw = {"width": w} if w else {}
        outer = tk.Frame(parent, bg=C["border"], padx=1, pady=1, **kw)
        inner = tk.Frame(outer, bg=C["bg2"]); inner.pack(fill=tk.BOTH, expand=True)
        if title:
            hdr = tk.Frame(inner, bg=C["bg3"], pady=4); hdr.pack(fill=tk.X)
            tk.Label(hdr, text=f"  {title}", font=("Consolas", 7, "bold"),
                     fg=C["text3"], bg=C["bg3"]).pack(side=tk.LEFT)
        return inner
 
    def _build_stat_grid(self, parent):
        g = tk.Frame(parent, bg=C["bg2"]); g.pack(fill=tk.X, padx=8, pady=8)
        for i, (lbl, col) in enumerate([("CRITICAL", C["red"]), ("HIGH", C["orange"]),
                                         ("MEDIUM", C["yellow"]), ("LOW", C["green"]),
                                         ("INFO", C["cyan"]), ("TOTAL", C["text"])]):
            r, c = divmod(i, 3)
            cell = tk.Frame(g, bg=C["bg3"], padx=8, pady=6)
            cell.grid(row=r, column=c, padx=2, pady=2, sticky="ew")
            g.columnconfigure(c, weight=1)
            tk.Label(cell, text=lbl, font=("Consolas", 6, "bold"),
                     fg=C["text3"], bg=C["bg3"]).pack(anchor="w")
            sv = tk.StringVar(value="—"); self._stat_vars[lbl] = sv
            tk.Label(cell, textvariable=sv, font=("Consolas", 17, "bold"),
                     fg=col, bg=C["bg3"]).pack(anchor="w")
            mb = MiniBar(cell, col); mb.pack(fill=tk.X, pady=(2, 0))
            self._stat_vars[lbl + "_bar"] = mb
        tf = tk.Frame(parent, bg=C["bg2"]); tf.pack(fill=tk.X, padx=8, pady=(0, 8))
        tk.Label(tf, text="LAST TARGET", font=("Consolas", 6, "bold"),
                 fg=C["text3"], bg=C["bg2"]).pack(anchor="w")
        self._tgt_var = tk.StringVar(value="None scanned yet")
        tk.Label(tf, textvariable=self._tgt_var, font=("Consolas", 9),
                 fg=C["accent"], bg=C["bg2"]).pack(anchor="w")
        self._ts_var = tk.StringVar(value="")
        tk.Label(tf, textvariable=self._ts_var, font=("Consolas", 7),
                 fg=C["text3"], bg=C["bg2"]).pack(anchor="w")
 
    def _build_sev_guide(self, parent):
        f = tk.Frame(parent, bg=C["bg2"]); f.pack(fill=tk.X, padx=8, pady=8)
        for sev, desc, col in [("CRITICAL", "Immediate action required", C["red"]),
                                ("HIGH", "Fix within 24-48 hours", C["orange"]),
                                ("MEDIUM", "Address next sprint", C["yellow"]),
                                ("LOW", "Monitor / best practice", C["green"]),
                                ("INFO", "Informational only", C["cyan"])]:
            row = tk.Frame(f, bg=C["bg3"], padx=8, pady=4); row.pack(fill=tk.X, pady=2)
            tk.Frame(row, bg=col, width=3).pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
            inn = tk.Frame(row, bg=C["bg3"]); inn.pack(side=tk.LEFT)
            tk.Label(inn, text=sev, font=("Consolas", 8, "bold"), fg=col, bg=C["bg3"]).pack(anchor="w")
            tk.Label(inn, text=desc, font=("Consolas", 7), fg=C["text3"], bg=C["bg3"]).pack(anchor="w")
 
    def _build_sys_status(self, parent):
        f = tk.Frame(parent, bg=C["bg2"]); f.pack(fill=tk.X, padx=8, pady=8)
        for lbl, st, col in [("Port Scanner", "READY", C["green"]),
                              ("SSL Engine", "ACTIVE", C["green"]),
                              ("DNS Resolver", "OK", C["green"]),
                              ("Header Check", "OK", C["green"]),
                              ("Vuln Database", "27 ports", C["cyan"]),
                              ("Header DB", "10 headers", C["cyan"])]:
            row = tk.Frame(f, bg=C["bg3"], padx=8, pady=4); row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=lbl, font=("Consolas", 8), fg=C["text2"],
                     bg=C["bg3"], width=14, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=st, font=("Consolas", 7, "bold"),
                     fg=col, bg=C["bg3"]).pack(side=tk.RIGHT)
 
    def _tick_clock(self):
        self._clk.set(datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self._clock_aid = self.after(1000, self._tick_clock)
 
    def update_results(self, findings, target):
        totals = defaultdict(int)
        for f in findings: totals[f.get("severity", "INFO")] += 1
        total = len(findings)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL"]:
            sv = self._stat_vars.get(sev)
            if sv: sv.set(str(total if sev == "TOTAL" else totals.get(sev, 0)))
        maxv = max(total, 1)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            mb = self._stat_vars.get(sev + "_bar")
            if mb: mb.set(totals.get(sev, 0) / maxv * 100)
        crit = totals["CRITICAL"]; high = totals["HIGH"]; med = totals["MEDIUM"]
        self.meter.set_val(min(100, crit * 25 + high * 12 + med * 5))
        self._tgt_var.set(target)
        self._ts_var.set(datetime.datetime.now().strftime("Scanned %H:%M:%S"))
        for w in self._findings_box.winfo_children(): w.destroy()
        if not findings:
            tk.Label(self._findings_box, text="  No findings.",
                     font=("Consolas", 9), fg=C["text3"], bg=C["bg2"], pady=10).pack(fill=tk.X)
            return
        for f in findings[:14]:
            sev = f.get("severity", "INFO"); col = SEV_COL.get(sev, C["cyan"])
            row = tk.Frame(self._findings_box, bg=C["bg3"])
            row.pack(fill=tk.X, pady=1)
            tk.Frame(row, bg=col, width=3).pack(side=tk.LEFT, fill=tk.Y)
            inn = tk.Frame(row, bg=C["bg3"])
            inn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=4)
            tk.Label(inn, text=f.get("title", ""), font=("Consolas", 8, "bold"),
                     fg=C["text"], bg=C["bg3"], anchor="w").pack(fill=tk.X)
            tk.Label(inn, text=f"{sev}  ·  {f.get('id', '')}",
                     font=("Consolas", 7), fg=col, bg=C["bg3"], anchor="w").pack(fill=tk.X)
 
# ═══════════════════════════════════════════════════
#  SCANNER PANEL
# ═══════════════════════════════════════════════════
class ScannerPanel(tk.Frame):
    def __init__(self,parent,app,**kw):
        super().__init__(parent,bg=C["bg1"],**kw)
        self._app=app; self._scanning=False
        self._findings=[]; self._widgets=[]; self._start_t=0
        self._build()
 
    def _build(self):
        # control bar
        ctrl=tk.Frame(self,bg=C["bg2"],padx=14,pady=10); ctrl.pack(fill=tk.X)
        tk.Label(ctrl,text="TARGET",font=("Consolas",7,"bold"),fg=C["text3"],bg=C["bg2"]).pack(anchor="w")
        row=tk.Frame(ctrl,bg=C["bg2"]); row.pack(fill=tk.X,pady=(4,0))
        ef=tk.Frame(row,bg=C["border2"],padx=1,pady=1); ef.pack(side=tk.LEFT,padx=(0,8))
        ei=tk.Frame(ef,bg=C["bg3"]); ei.pack()
        self._tvar=tk.StringVar(value="scanme.nmap.org")
        self._entry=tk.Entry(ei,textvariable=self._tvar,font=("Consolas",11),
                              fg=C["text"],bg=C["bg3"],insertbackground=C["accent"],
                              relief=tk.FLAT,bd=0,width=30)
        self._entry.pack(ipady=8,ipadx=10)
        self._entry.bind("<Return>",lambda e:self._start())
        self._entry.bind("<FocusIn>",lambda e:ef.config(bg=C["accent2"]))
        self._entry.bind("<FocusOut>",lambda e:ef.config(bg=C["border2"]))
        self._btnf=tk.Frame(row,bg=C["bg2"]); self._btnf.pack(side=tk.LEFT)
        self._make_btn(True)
        self._opt_ports=tk.BooleanVar(value=True)
        self._opt_ssl=tk.BooleanVar(value=True)
        self._opt_hdr=tk.BooleanVar(value=True)
        opts=tk.Frame(row,bg=C["bg2"]); opts.pack(side=tk.LEFT,padx=14)
        for lbl,var in [("Ports",self._opt_ports),("SSL",self._opt_ssl),("Headers",self._opt_hdr)]:
            cf=tk.Frame(opts,bg=C["bg3"],padx=6,pady=3); cf.pack(side=tk.LEFT,padx=2)
            tk.Checkbutton(cf,text=lbl,variable=var,font=("Consolas",8),
                           fg=C["text2"],bg=C["bg3"],selectcolor=C["bg5"],
                           activebackground=C["bg3"],activeforeground=C["text"],
                           relief=tk.FLAT,bd=0,highlightthickness=0).pack()
        sr=tk.Frame(ctrl,bg=C["bg2"],pady=2); sr.pack(fill=tk.X)
        self._svar=tk.StringVar(value="Ready — enter a hostname or IP above")
        self._slbl=tk.Label(sr,textvariable=self._svar,font=("Consolas",8),fg=C["text3"],bg=C["bg2"])
        self._slbl.pack(side=tk.LEFT)
        self._tvar2=tk.StringVar(value="")
        tk.Label(sr,textvariable=self._tvar2,font=("Consolas",8,"bold"),
                 fg=C["accent"],bg=C["bg2"]).pack(side=tk.RIGHT)
        self._pbar=ProgressBar(ctrl,h=2); self._pbar.pack(fill=tk.X,pady=(6,0))
        tk.Frame(self,bg=C["border"],height=1).pack(fill=tk.X)
        # paned: log | findings
        panes=tk.PanedWindow(self,orient=tk.HORIZONTAL,bg=C["border"],
                              sashwidth=3,sashrelief=tk.FLAT)
        panes.pack(fill=tk.BOTH,expand=True)
        # log
        lo=tk.Frame(panes,bg=C["bg1"]); panes.add(lo,minsize=260)
        lh=tk.Frame(lo,bg=C["bg2"],pady=4); lh.pack(fill=tk.X)
        tk.Label(lh,text="  LIVE LOG",font=("Consolas",7,"bold"),fg=C["text3"],bg=C["bg2"]).pack(side=tk.LEFT)
        self._dot=PulseDot(lh,font=("Consolas",9),fg=C["text3"],bg=C["bg2"])
        self._dot.pack(side=tk.LEFT,padx=5)
        self._log=tk.Text(lo,font=("Consolas",9),fg=C["text"],bg=C["bg1"],
                           insertbackground=C["accent"],relief=tk.FLAT,bd=0,
                           state=tk.DISABLED,wrap=tk.WORD,padx=10,pady=6,
                           selectbackground=C["bg5"])
        self._log.pack(fill=tk.BOTH,expand=True)
        for k,v in [("accent",C["accent"]),("green",C["green"]),("red",C["red"]),
                    ("yellow",C["yellow"]),("text2",C["text2"]),("text3",C["text3"]),
                    ("border3",C["border3"]),("orange",C["orange"]),("cyan",C["cyan"])]:
            self._log.tag_configure(k,foreground=v)
        # findings
        ro=tk.Frame(panes,bg=C["bg2"]); panes.add(ro,minsize=400)
        fh=tk.Frame(ro,bg=C["bg2"],pady=5,padx=10); fh.pack(fill=tk.X)
        tk.Label(fh,text="FINDINGS",font=("Consolas",7,"bold"),fg=C["text3"],bg=C["bg2"]).pack(side=tk.LEFT)
        self._cnt=tk.StringVar(value="")
        tk.Label(fh,textvariable=self._cnt,font=("Consolas",7,"bold"),fg=C["accent"],bg=C["bg2"]).pack(side=tk.LEFT,padx=5)
        self._expbtn=tk.Button(fh,text="↓ Export",font=("Consolas",7),
                                fg=C["text2"],bg=C["bg3"],activeforeground=C["text"],
                                activebackground=C["bg5"],relief=tk.FLAT,bd=0,
                                padx=7,pady=2,cursor="hand2",
                                command=self._export,state=tk.DISABLED)
        self._expbtn.pack(side=tk.RIGHT)
        fb=tk.Frame(ro,bg=C["bg3"],pady=4,padx=10); fb.pack(fill=tk.X)
        tk.Label(fb,text="FILTER",font=("Consolas",6,"bold"),fg=C["text3"],bg=C["bg3"]).pack(side=tk.LEFT,padx=(0,6))
        self._flt="ALL"; self._fbtns={}
        for lbl in ["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            col=SEV_COL.get(lbl,C["text2"])
            b=tk.Button(fb,text=lbl,font=("Consolas",6,"bold"),fg=col,bg=C["bg5"],
                        activeforeground=col,activebackground=C["bg6"] if "bg6" in C else C["bg5"],
                        relief=tk.FLAT,bd=0,padx=7,pady=2,cursor="hand2",
                        command=lambda l=lbl:self._apply_filter(l))
            b.pack(side=tk.LEFT,padx=1); self._fbtns[lbl]=b
        tk.Frame(ro,bg=C["border"],height=1).pack(fill=tk.X)
        self._sf=ScrollFrame(ro,bg=C["bg2"]); self._sf.pack(fill=tk.BOTH,expand=True)
        panes.paneconfig(lo,width=380); panes.paneconfig(ro,width=680)
 
    def _make_btn(self,idle):
        for w in self._btnf.winfo_children(): w.destroy()
        if idle:
            b=tk.Button(self._btnf,text="▶  SCAN",command=self._start,
                        font=("Consolas",9,"bold"),fg=C["text"],bg=C["bg4"],
                        activeforeground=C["text"],activebackground=C["bg5"],
                        relief=tk.FLAT,bd=0,padx=14,pady=6,cursor="hand2")
        else:
            b=tk.Button(self._btnf,text="■  STOP",command=self._stop,
                        font=("Consolas",9,"bold"),fg=C["red"],bg=C["red_bg"],
                        activeforeground=C["red"],activebackground=C["red2"],
                        relief=tk.FLAT,bd=0,padx=14,pady=6,cursor="hand2")
        b.pack()
 
    def _start(self):
        if self._scanning: return
        tgt=self._tvar.get().strip()
        if not tgt: messagebox.showwarning("No target","Enter a hostname or IP."); return
        self._scanning=True; self._findings=[]; self._widgets.clear()
        for w in self._sf.inner.winfo_children(): w.destroy()
        self._log.config(state=tk.NORMAL); self._log.delete("1.0",tk.END)
        self._log.config(state=tk.DISABLED)
        self._cnt.set(""); self._expbtn.config(state=tk.DISABLED)
        self._make_btn(False); self._dot.start(C["green"])
        self._pbar.set(0); self._start_t=time.time(); self._tick()
        self._write_log(f"  ┌─────────────────────────────────────────","text3")
        self._write_log(f"  │  SCANNERWIBE_2.0  ·  Target: {tgt}","accent")
        self._write_log(f"  │  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}","text3")
        self._write_log(f"  └─────────────────────────────────────────\n","text3")
        opts={"port_scan":self._opt_ports.get(),"ssl":self._opt_ssl.get(),
              "headers":self._opt_hdr.get()}
        threading.Thread(target=run_scan,
            args=(tgt,opts,self._cb_prog,self._cb_find,self._cb_log,self._cb_done),
            daemon=True).start()
 
    def _stop(self):
        self._scanning=False; self._make_btn(True)
        self._dot.stop(C["yellow"]); self._write_log("  Stopped.","yellow")
 
    def _tick(self):
        if not self._scanning: return
        self._tvar2.set(f"{time.time()-self._start_t:.1f}s"); self.after(100,self._tick)
 
    def _write_log(self,msg,tag="text"):
        self._log.config(state=tk.NORMAL)
        self._log.insert(tk.END,msg+"\n",tag)
        self._log.see(tk.END); self._log.config(state=tk.DISABLED)
 
    def _cb_prog(self,v,lbl):
        self.after(0,lambda:self._pbar.set(v))
        self.after(0,lambda:self._svar.set(lbl))
 
    def _cb_log(self,msg,tag="text"):
        self.after(0,lambda:self._write_log(msg,tag))
 
    def _cb_find(self,finding):
        def _do():
            card=FindingCard(self._sf.inner,finding)
            card.pack(fill=tk.X,padx=5,pady=2)
            self._widgets.append((finding.get("severity","INFO"),card))
            self._findings.append(finding)
            self._cnt.set(f"  {len(self._findings)} found")
        self.after(0,_do)
 
    def _cb_done(self,findings):
        def _do():
            self._scanning=False; self._make_btn(True)
            self._dot.stop(C["green"] if findings else C["text3"])
            self._tvar2.set(f"{time.time()-self._start_t:.1f}s")
            self._svar.set(f"Complete — {len(findings)} finding(s)")
            if findings: self._expbtn.config(state=tk.NORMAL)
            self._app.on_scan_done(findings,self._tvar.get())
        self.after(0,_do)
 
    def _apply_filter(self,lvl):
        self._flt=lvl
        for l,b in self._fbtns.items(): b.config(bg=C["bg5"])
        self._fbtns[lvl].config(bg=C["bg3"])
        for sev,w in self._widgets:
            if lvl=="ALL" or sev==lvl: w.pack(fill=tk.X,padx=5,pady=2)
            else: w.pack_forget()
 
    def _export(self):
        fn=filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON","*.json")],
            initialfile=f"sentinel_{datetime.datetime.now():%Y%m%d_%H%M%S}.json")
        if not fn: return
        with open(fn,"w",encoding="utf-8") as fh:
            json.dump({"target":self._tvar.get(),"tool":"Sentinel v5",
                       "scan_time":datetime.datetime.now().isoformat(),
                       "findings":self._findings},fh,indent=2)
        messagebox.showinfo("Exported",f"Saved:\n{fn}")
 
# ═══════════════════════════════════════════════════
#  PORT REFERENCE PANEL
# ═══════════════════════════════════════════════════
class PortRefPanel(tk.Frame):
    def __init__(self,parent,app,**kw):
        super().__init__(parent,bg=C["bg1"],**kw)
        self._app=app; self._rows=[]; self._build()
 
    def _build(self):
        hdr=tk.Frame(self,bg=C["bg2"],padx=14,pady=10); hdr.pack(fill=tk.X)
        tk.Label(hdr,text="PORT REFERENCE DATABASE",font=("Consolas",10,"bold"),
                 fg=C["text"],bg=C["bg2"]).pack(side=tk.LEFT)
        tk.Label(hdr,text=f"  {len(COMMON_PORTS)} entries",font=("Consolas",8),
                 fg=C["text3"],bg=C["bg2"]).pack(side=tk.LEFT)
        tk.Frame(self,bg=C["border"],height=1).pack(fill=tk.X)
        sf=tk.Frame(self,bg=C["bg1"],padx=14,pady=8); sf.pack(fill=tk.X)
        ef=tk.Frame(sf,bg=C["border2"],padx=1,pady=1); ef.pack(fill=tk.X)
        ei=tk.Frame(ef,bg=C["bg3"]); ei.pack(fill=tk.X)
        self._sv=tk.StringVar(); self._sv.trace("w",lambda *_:self._filter())
        tk.Entry(ei,textvariable=self._sv,font=("Consolas",10),fg=C["text"],
                 bg=C["bg3"],insertbackground=C["accent"],relief=tk.FLAT,bd=0
                 ).pack(fill=tk.X,ipady=7,ipadx=10)
        tk.Frame(self,bg=C["border"],height=1).pack(fill=tk.X)
        ch=tk.Frame(self,bg=C["bg3"],padx=14,pady=5); ch.pack(fill=tk.X)
        for txt,w in [("PORT",6),("SERVICE",14),("RISK",11),("DESCRIPTION",0)]:
            tk.Label(ch,text=txt,font=("Consolas",7,"bold"),fg=C["text3"],
                     bg=C["bg3"],width=w,anchor="w").pack(side=tk.LEFT)
        self._sf=ScrollFrame(self,bg=C["bg1"]); self._sf.pack(fill=tk.BOTH,expand=True)
        for port,(svc,desc) in sorted(COMMON_PORTS.items()):
            danger=port in DANGEROUS
            col=C["red"] if danger else C["green"]
            row=tk.Frame(self._sf.inner,bg=C["bg2"]); row.pack(fill=tk.X)
            tk.Frame(row,bg=col,width=3).pack(side=tk.LEFT,fill=tk.Y)
            inn=tk.Frame(row,bg=C["bg2"]); inn.pack(fill=tk.X,expand=True,padx=4,pady=5)
            tk.Label(inn,text=str(port),font=("Consolas",9,"bold"),fg=col,
                     bg=C["bg2"],width=6,anchor="w").pack(side=tk.LEFT)
            tk.Label(inn,text=svc,font=("Consolas",8,"bold"),fg=C["text"],
                     bg=C["bg2"],width=14,anchor="w").pack(side=tk.LEFT)
            tk.Label(inn,text="DANGEROUS" if danger else "STANDARD",
                     font=("Consolas",7,"bold"),fg=col,bg=C["bg2"],width=11,anchor="w").pack(side=tk.LEFT)
            tk.Label(inn,text=desc,font=("Consolas",8),fg=C["text2"],
                     bg=C["bg2"],anchor="w").pack(side=tk.LEFT,fill=tk.X,expand=True)
            sep=tk.Frame(self._sf.inner,bg=C["border"],height=1); sep.pack(fill=tk.X)
            self._rows.append((port,svc,desc,row,sep))
 
    def _filter(self):
        q=self._sv.get().lower()
        for port,svc,desc,row,sep in self._rows:
            show=not q or q in str(port) or q in svc.lower() or q in desc.lower()
            if show: row.pack(fill=tk.X); sep.pack(fill=tk.X)
            else: row.pack_forget(); sep.pack_forget()
 
# ═══════════════════════════════════════════════════
#  HEADER REFERENCE PANEL
# ═══════════════════════════════════════════════════
class HeaderRefPanel(tk.Frame):
    def __init__(self,parent,app,**kw):
        super().__init__(parent,bg=C["bg1"],**kw)
        self._app=app; self._build()
 
    def _build(self):
        hdr=tk.Frame(self,bg=C["bg2"],padx=14,pady=10); hdr.pack(fill=tk.X)
        tk.Label(hdr,text="HTTP SECURITY HEADERS",font=("Consolas",10,"bold"),
                 fg=C["text"],bg=C["bg2"]).pack(side=tk.LEFT)
        tk.Frame(self,bg=C["border"],height=1).pack(fill=tk.X)
        sf=ScrollFrame(self,bg=C["bg1"]); sf.pack(fill=tk.BOTH,expand=True)
        for hname,(abbr,desc,sev) in SEC_HEADERS.items():
            col=SEV_COL.get(sev,C["cyan"])
            card=tk.Frame(sf.inner,bg=C["bg2"],highlightthickness=1,
                          highlightbackground=C["border"]); card.pack(fill=tk.X,padx=8,pady=4)
            tk.Frame(card,bg=col,width=3).pack(side=tk.LEFT,fill=tk.Y)
            body=tk.Frame(card,bg=C["bg2"]); body.pack(side=tk.LEFT,fill=tk.X,expand=True,padx=10,pady=8)
            top=tk.Frame(body,bg=C["bg2"]); top.pack(fill=tk.X)
            tf=tk.Frame(top,bg=col,padx=6,pady=1); tf.pack(side=tk.LEFT,padx=(0,7))
            tk.Label(tf,text=abbr,font=("Consolas",7,"bold"),fg=C["bg"],bg=col).pack()
            sf2=tk.Frame(top,bg=C["bg3"],padx=5,pady=1); sf2.pack(side=tk.LEFT,padx=(0,7))
            tk.Label(sf2,text=sev,font=("Consolas",7,"bold"),fg=col,bg=C["bg3"]).pack()
            tk.Label(top,text=hname,font=("Consolas",9,"bold"),fg=C["text"],bg=C["bg2"]).pack(side=tk.LEFT)
            tk.Label(body,text=desc,font=("Consolas",8),fg=C["text2"],bg=C["bg2"],anchor="w").pack(fill=tk.X,pady=(3,0))
            fix=HEADER_FIXES.get(hname,"")
            if fix:
                ff=tk.Frame(body,bg=C["bg3"],padx=7,pady=5); ff.pack(fill=tk.X,pady=(5,0))
                tk.Label(ff,text="FIX",font=("Consolas",6,"bold"),fg=C["green"],bg=C["bg3"]).pack(anchor="w")
                tk.Label(ff,text=fix,font=("Consolas",8),fg=C["text2"],
                         bg=C["bg3"],anchor="w",justify=tk.LEFT).pack(fill=tk.X)
 
# ═══════════════════════════════════════════════════
#  HISTORY PANEL
# ═══════════════════════════════════════════════════
class HistoryPanel(tk.Frame):
    def __init__(self,parent,app,**kw):
        super().__init__(parent,bg=C["bg1"],**kw)
        self._app=app; self._history=[]; self._build()
 
    def _build(self):
        hdr=tk.Frame(self,bg=C["bg2"],padx=14,pady=10); hdr.pack(fill=tk.X)
        tk.Label(hdr,text="SCAN HISTORY",font=("Consolas",10,"bold"),
                 fg=C["text"],bg=C["bg2"]).pack(side=tk.LEFT)
        tk.Button(hdr,text="✕ Clear",font=("Consolas",8),fg=C["text3"],bg=C["bg3"],
                  activeforeground=C["red"],activebackground=C["bg4"],
                  relief=tk.FLAT,bd=0,padx=7,pady=2,cursor="hand2",
                  command=self._clear).pack(side=tk.RIGHT)
        tk.Frame(self,bg=C["border"],height=1).pack(fill=tk.X)
        ch=tk.Frame(self,bg=C["bg3"],padx=14,pady=5); ch.pack(fill=tk.X)
        for txt in ["TIMESTAMP","TARGET","TOTAL","CRITICAL","HIGH","DURATION"]:
            tk.Label(ch,text=txt,font=("Consolas",7,"bold"),fg=C["text3"],
                     bg=C["bg3"],anchor="w",width=12).pack(side=tk.LEFT)
        tk.Frame(self,bg=C["border"],height=1).pack(fill=tk.X)
        self._sf=ScrollFrame(self,bg=C["bg1"]); self._sf.pack(fill=tk.BOTH,expand=True)
        self._empty=tk.Label(self._sf.inner,
            text="\n  No scans yet — run a scan from the Scanner tab.\n",
            font=("Consolas",9),fg=C["text3"],bg=C["bg1"])
        self._empty.pack(pady=30)
 
    def add_entry(self,target,findings,duration):
        self._empty.pack_forget()
        ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        crit=sum(1 for f in findings if f.get("severity")=="CRITICAL")
        high=sum(1 for f in findings if f.get("severity")=="HIGH")
        e={"ts":ts,"target":target,"total":len(findings),"crit":crit,"high":high,
           "dur":f"{duration:.1f}s"}
        self._history.insert(0,e)
        col=C["red"] if crit>0 else C["orange"] if high>0 else C["green"]
        kids=self._sf.inner.winfo_children()
        row=tk.Frame(self._sf.inner,bg=C["bg2"])
        if kids: row.pack(fill=tk.X,before=kids[0])
        else: row.pack(fill=tk.X)
        tk.Frame(row,bg=col,width=3).pack(side=tk.LEFT,fill=tk.Y)
        inn=tk.Frame(row,bg=C["bg2"]); inn.pack(fill=tk.X,expand=True,padx=8,pady=7)
        for val,vc,w in [(e["ts"],C["text3"],12),(e["target"],C["cyan"],12),
                         (str(e["total"]),C["text"],12),(str(e["crit"]),C["red"],12),
                         (str(e["high"]),C["orange"],12),(e["dur"],C["text2"],12)]:
            tk.Label(inn,text=val,font=("Consolas",8),fg=vc,bg=C["bg2"],
                     anchor="w",width=w).pack(side=tk.LEFT)
        tk.Frame(self._sf.inner,bg=C["border"],height=1).pack(fill=tk.X)
 
    def _clear(self):
        self._history.clear()
        for w in self._sf.inner.winfo_children(): w.destroy()
        self._empty=tk.Label(self._sf.inner,
            text="\n  No scans yet — run a scan from the Scanner tab.\n",
            font=("Consolas",9),fg=C["text3"],bg=C["bg1"])
        self._empty.pack(pady=30)
 
# ═══════════════════════════════════════════════════
#  ABOUT PANEL
# ═══════════════════════════════════════════════════
class AboutPanel(tk.Frame):
    def __init__(self,parent,app,**kw):
        super().__init__(parent,bg=C["bg1"],**kw)
        self._app=app; self._build()
 
    def _build(self):
        hdr=tk.Frame(self,bg=C["bg2"],padx=14,pady=10); hdr.pack(fill=tk.X)
        tk.Label(hdr,text="ABOUT  &  HELP",font=("Consolas",10,"bold"),
                 fg=C["text"],bg=C["bg2"]).pack(side=tk.LEFT)
        tk.Frame(self,bg=C["border"],height=1).pack(fill=tk.X)
        sf=ScrollFrame(self,bg=C["bg1"]); sf.pack(fill=tk.BOTH,expand=True)
        body=tk.Frame(sf.inner,bg=C["bg1"]); body.pack(fill=tk.BOTH,padx=18,pady=18)
        lf=tk.Frame(body,bg=C["bg2"],padx=20,pady=16,highlightthickness=1,
                    highlightbackground=C["border3"]); lf.pack(fill=tk.X,pady=(0,14))
        lc=tk.Canvas(lf,width=44,height=44,bg=C["bg2"],highlightthickness=0); lc.pack(side=tk.LEFT,padx=(0,14))
        cx=cy=22; r=19; pts=[]
        for i in range(6):
            a=math.radians(60*i-30); pts+=[cx+r*math.cos(a),cy+r*math.sin(a)]
        lc.create_polygon(pts,fill=C["bg4"],outline=C["accent"],width=2)
        lc.create_text(cx,cy,text="S",font=("Consolas",16,"bold"),fill=C["text"])
        info=tk.Frame(lf,bg=C["bg2"]); info.pack(side=tk.LEFT)
        tk.Label(info,text="SCANNERWIBE_2.0",font=("Consolas",16,"bold"),fg=C["text"],bg=C["bg2"]).pack(anchor="w")
        tk.Label(info,text="Cyber Operations Centre",font=("Consolas",9),fg=C["accent2"],bg=C["bg2"]).pack(anchor="w")
        tk.Label(info,text="Single-file · Python 3.8+ · No pip dependencies",
                 font=("Consolas",8),fg=C["text3"],bg=C["bg2"]).pack(anchor="w")
        for title,text in [
            ("OVERVIEW",
             "SCANNERWIBE_2.0 is a professional-grade network security scanner.\n"
             "Port scanning, TLS/SSL certificate checks, HTTP security headers,\n"
             "and vulnerability correlation — all in a single Python file."),
            ("LEGAL NOTICE",
             "Only scan hosts you own or have written permission to test.\n"
             "Unauthorized scanning may be illegal in your jurisdiction.\n"
             "scanme.nmap.org is safe to use for testing."),
            ("SCAN MODULES",
             "Port Scan    — 28 well-known ports, 1s timeout each\n"
             "SSL / TLS    — Certificate validity, expiry, cipher checks\n"
             "HTTP Headers — 10 OWASP-recommended security headers"),
        ]:
            sf2=tk.Frame(body,bg=C["bg3"],padx=14,pady=10,highlightthickness=1,
                         highlightbackground=C["border"]); sf2.pack(fill=tk.X,pady=5)
            tk.Label(sf2,text=title,font=("Consolas",8,"bold"),fg=C["accent"],bg=C["bg3"]).pack(anchor="w")
            tk.Frame(sf2,bg=C["border2"],height=1).pack(fill=tk.X,pady=(3,7))
            tk.Label(sf2,text=text,font=("Consolas",9),fg=C["text2"],
                     bg=C["bg3"],anchor="w",justify=tk.LEFT).pack(fill=tk.X)
 
# ═══════════════════════════════════════════════════
#  MAIN APPLICATION  — SCANNERWIBE 2.0
# ═══════════════════════════════════════════════════
class ScannerWibeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ScannerWibe 2.0 — Cyber Operations Centre")
        self.geometry("1280x800"); self.minsize(1000,640)
        self.configure(bg=C["bg"])
        self._current = None
        self._build()
 
    def _build(self):
        # ══════════════════════════════════════════
        # TOP BAR  —  logo + glow bars + tabs + clock
        # ══════════════════════════════════════════
        topbar = tk.Frame(self, bg=C["bg2"], height=54)
        topbar.pack(fill=tk.X, side=tk.TOP)
        topbar.pack_propagate(False)
 
        # ── Logo block ─────────────────────────────
        logo_block = tk.Frame(topbar, bg=C["bg2"], padx=14)
        logo_block.pack(side=tk.LEFT, fill=tk.Y)
 
        # Hexagon icon
        lc = tk.Canvas(logo_block, width=28, height=28,
                        bg=C["bg2"], highlightthickness=0)
        lc.pack(side=tk.LEFT, pady=13, padx=(0, 0))
        cx = cy = 14; r = 12; pts = []
        for i in range(6):
            a = math.radians(60*i - 30)
            pts += [cx + r*math.cos(a), cy + r*math.sin(a)]
        lc.create_polygon(pts, fill=C["bg4"], outline=C["cyan"], width=1)
        lc.create_text(cx, cy, text="SW", font=("Consolas", 7, "bold"),
                        fill=C["cyan"])
 
        # Name label
        name_frame = tk.Frame(logo_block, bg=C["bg2"])
        name_frame.pack(side=tk.LEFT, padx=(8, 0), pady=0, fill=tk.Y)
        name_inner = tk.Frame(name_frame, bg=C["bg2"])
        name_inner.pack(side=tk.LEFT, anchor="center", pady=13)
        tk.Label(name_inner, text="SCANNERWIBE",
                 font=("Consolas", 11, "bold"),
                 fg=C["text"], bg=C["bg2"]).pack(side=tk.LEFT)
        tk.Label(name_inner, text=" 2.0",
                 font=("Consolas", 9, "bold"),
                 fg=C["cyan"], bg=C["bg2"]).pack(side=tk.LEFT)
 
        # ── Glow bars right after the name ────────
        glow_sep = tk.Frame(topbar, bg=C["border"], width=1)
        glow_sep.pack(side=tk.LEFT, fill=tk.Y, pady=10)
 
        glow_frame = tk.Frame(topbar, bg=C["bg2"], padx=10)
        glow_frame.pack(side=tk.LEFT, fill=tk.Y)
        self._glow_bars = TopbarGlowBars(glow_frame, height=34)
        self._glow_bars.pack(side=tk.LEFT, anchor="center", pady=10)
 
        # ── Tab separator ──────────────────────────
        tab_sep = tk.Frame(topbar, bg=C["border"], width=1)
        tab_sep.pack(side=tk.LEFT, fill=tk.Y, pady=10)
 
        # ── Tab buttons ────────────────────────────
        tabs = [
            ("dashboard", "\u2b21  DASHBOARD"),
            ("scanner",   "\u25ce  SCANNER"),
            ("portref",   "\u229e  PORT REF"),
            ("headerref", "\u2261  HEADERS"),
            ("history",   "\u25f7  HISTORY"),
            ("about",     "?  ABOUT"),
        ]
        self._tab_btns = {}
        for key, label in tabs:
            btn = tk.Button(
                topbar, text=label,
                font=("Consolas", 8, "bold"),
                fg=C["text3"], bg=C["bg2"],
                activeforeground=C["text"],
                activebackground=C["bg3"],
                relief=tk.FLAT, bd=0,
                padx=14, pady=0,
                cursor="hand2",
                command=lambda k=key: self._show(k))
            btn.pack(side=tk.LEFT, fill=tk.Y)
            btn.bind("<Enter>", lambda e, b=btn, k=key:
                     b.config(fg=C["text"], bg=C["bg3"])
                     if self._current != k else None)
            btn.bind("<Leave>", lambda e, b=btn, k=key:
                     b.config(fg=C["text3"], bg=C["bg2"])
                     if self._current != k else None)
            self._tab_btns[key] = btn
 
        # ── Clock ──────────────────────────────────
        self._clk = tk.StringVar()
        tk.Label(topbar, textvariable=self._clk,
                 font=("Consolas", 8),
                 fg=C["text3"], bg=C["bg2"],
                 padx=14).pack(side=tk.RIGHT, fill=tk.Y)
        self._tick_clk()
 
        # ══════════════════════════════════════════
        # ACCENT LINE — cyan glow strip under topbar
        # ══════════════════════════════════════════
        accent_line = tk.Canvas(self, height=2, bg=C["bg"],
                                highlightthickness=0)
        accent_line.pack(fill=tk.X, side=tk.TOP)
 
        def _draw_accent(e=None):
            accent_line.delete("all")
            w = accent_line.winfo_width()
            if w < 2:
                return
            # left third: cyan
            accent_line.create_rectangle(
                0, 0, w//3, 2, fill=C["cyan"], outline="")
            # middle third: purple
            accent_line.create_rectangle(
                w//3, 0, 2*w//3, 2, fill=C["purple"], outline="")
            # right third: green
            accent_line.create_rectangle(
                2*w//3, 0, w, 2, fill=C["green"], outline="")
 
        accent_line.bind("<Configure>", _draw_accent)
 
        # ══════════════════════════════════════════
        # CONTENT AREA
        # ══════════════════════════════════════════
        self._content = tk.Frame(self, bg=C["bg1"])
        self._content.pack(fill=tk.BOTH, expand=True)
 
        self._panels = {}
        self._panels["dashboard"] = DashboardPanel(self._content, self)
        self._panels["scanner"]   = ScannerPanel(self._content, self)
        self._panels["portref"]   = PortRefPanel(self._content, self)
        self._panels["headerref"] = HeaderRefPanel(self._content, self)
        self._panels["history"]   = HistoryPanel(self._content, self)
        self._panels["about"]     = AboutPanel(self._content, self)
 
        self._show("dashboard")
 
    def _tick_clk(self):
        self._clk.set(datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clk)
 
    def _show(self, key):
        # deactivate old tab
        if self._current and self._current in self._tab_btns:
            self._tab_btns[self._current].config(
                fg=C["text3"], bg=C["bg2"])
        # hide all panels
        for panel in self._panels.values():
            panel.pack_forget()
        # activate new tab — highlight with bottom border trick via bg
        self._current = key
        btn = self._tab_btns[key]
        btn.config(fg=C["cyan"], bg=C["bg3"])
        # show panel
        self._panels[key].pack(fill=tk.BOTH, expand=True)
        # radar + dashboard bars
        if key == "dashboard":
            self._panels["dashboard"].radar.start()
            self._panels["dashboard"]._bars.start()
        else:
            self._panels["dashboard"].radar.stop()
            self._panels["dashboard"]._bars.stop()
 
    def on_scan_done(self, findings, target):
        elapsed = time.time() - self._panels["scanner"]._start_t
        self._panels["dashboard"].update_results(findings, target)
        self._panels["history"].add_entry(target, findings, elapsed)
 
 
def main():
    print("""
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  SCANNERWIBE 2.0  --  Cyber Operations Centre          \u2551
\u2551  Glow bars  \xb7  Modern topbar  \xb7  Animated dashboard      \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
""")
    app = ScannerWibeApp()
    app.mainloop()
 
if __name__=="__main__":
    main()