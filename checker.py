"""
URLHaus Threat Intelligence Checker
Author: CyberSec Tool Suite
Description: Queries abuse.ch URLhaus database to detect and analyze live threats.
             Identifies malware distribution, phishing pages, and C2 servers.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import json
import re
import csv
import os
import sys
import datetime
from urllib.parse import urlparse


# ─────────────────────────────────────────────
#  ABUSE.CH API CONFIG
# ─────────────────────────────────────────────
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"

APP_VERSION = "1.0.0"
APP_TITLE   = "URLHaus Threat Intelligence Checker"


# ─────────────────────────────────────────────
#  THREAT TAXONOMY
# ─────────────────────────────────────────────
THREAT_LABELS = {
    "malware_download": ("Malware Distribution",  "#ff4444", "⚠"),
    "phishing":         ("Phishing Page",          "#ff8800", "🎣"),
    "botnet_cc":        ("Command & Control (C2)", "#cc00ff", "☠"),
    "exploit":          ("Exploit Kit",            "#ff0066", "💥"),
    "spam":             ("Spam Infrastructure",    "#ffcc00", "📧"),
    "other":            ("Other Threat",           "#999999", "❓"),
}


def classify_tags(tags: list) -> str:
    """Map URLhaus tags to internal threat categories."""
    if not tags:
        return "other"
    joined = " ".join(tags).lower()
    if any(k in joined for k in ["cc", "c2", "botnet", "rat", "trojan", "cobalt"]):
        return "botnet_cc"
    if any(k in joined for k in ["phish", "credential", "login"]):
        return "phishing"
    if any(k in joined for k in ["exploit", "ek", "kit"]):
        return "exploit"
    if "spam" in joined:
        return "spam"
    return "malware_download"


# ─────────────────────────────────────────────
#  CORE ANALYSIS ENGINE
# ─────────────────────────────────────────────

def query_urlhaus(url: str, timeout: int = 10) -> dict:
    """
    Query the URLhaus API for a single URL.
    Returns a normalised result dict.
    """
    result = {
        "queried_url":   url,
        "found":         False,
        "status":        "unknown",
        "threat":        None,
        "threat_label":  None,
        "threat_color":  "#aaaaaa",
        "threat_icon":   "❓",
        "tags":          [],
        "date_added":    None,
        "date_lastmod":  None,
        "reporter":      None,
        "reference":     None,
        "payloads":      [],
        "host":          None,
        "host_info":     None,
        "error":         None,
        "raw":           None,
        "timestamp":     datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
    }

    # ── basic URL validation ──────────────────────────────────────
    url = url.strip()
    if not url:
        result["error"] = "Empty URL provided."
        return result
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
        result["queried_url"] = url

    try:
        parsed = urlparse(url)
        result["host"] = parsed.hostname
    except Exception:
        result["error"] = "Invalid URL format."
        return result

    # ── URLhaus URL lookup ────────────────────────────────────────
    try:
        resp = requests.post(
            URLHAUS_API,
            data={"url": url},
            timeout=timeout,
            headers={"User-Agent": f"URLHaus-Checker/{APP_VERSION}"}
        )
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError:
            result["error"] = "Invalid JSON response from URLhaus API."
            return result
        result["raw"] = data
    except requests.exceptions.ConnectionError:
        result["error"] = "Network error – check your internet connection."
        return result
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out. URLhaus may be slow – retry."
        return result
    except requests.exceptions.HTTPError as e:
        result["error"] = f"HTTP {resp.status_code}: {e}"
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        return result

    query_status = data.get("query_status", "")

    if query_status == "no_results":
        result["found"]  = False
        result["status"] = "clean"
        return result

    if query_status == "is_host":
        # URL matched as host record (unlikely but handle gracefully)
        result["found"]  = True
        result["status"] = data.get("url_status", "unknown")
    elif query_status in ("is_url", "available"):
        result["found"]  = True
        result["status"] = data.get("url_status", "unknown")
    else:
        result["found"]  = False
        result["status"] = "unknown"
        return result

    # ── enrich from response ──────────────────────────────────────
    tags = data.get("tags") or []
    result["tags"]        = tags
    result["date_added"]  = data.get("date_added")
    result["date_lastmod"]= data.get("larted")         # typo in API
    result["reporter"]    = data.get("reporter")
    result["reference"]   = data.get("url_id") and \
                            f"https://urlhaus.abuse.ch/url/{data['url_id']}/"
    result["payloads"]    = data.get("payloads") or []

    # Threat type from API field or tag inference
    api_threat = data.get("threat") or ""
    if api_threat:
        cat = classify_tags([api_threat] + tags)
    else:
        cat = classify_tags(tags)

    label, color, icon = THREAT_LABELS.get(cat, ("Unknown Threat", "#999999", "❓"))
    result["threat"]       = cat
    result["threat_label"] = label
    result["threat_color"] = color
    result["threat_icon"]  = icon

    # ── optional host enrichment ──────────────────────────────────
    if result["host"]:
        try:
            hr = requests.post(
                URLHAUS_HOST_API,
                data={"host": result["host"]},
                timeout=timeout,
                headers={"User-Agent": f"URLHaus-Checker/{APP_VERSION}"}
            )
            if hr.ok:
                hdata = hr.json()
                if hdata.get("query_status") not in ("no_results", None):
                    result["host_info"] = {
                        "urls_on_host": hdata.get("urls_on_this_host", 0),
                        "blacklists":   hdata.get("blacklists", {}),
                        "first_seen":   hdata.get("firstseen"),
                    }
        except Exception:
            pass  # host enrichment is best-effort

    return result


# ─────────────────────────────────────────────
#  GUI APPLICATION
# ─────────────────────────────────────────────

class App(tk.Tk):
    HISTORY_FILE = os.path.join(
        os.path.expanduser("~"), ".urlhaus_checker_history.json"
    )

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1100x780")
        self.minsize(900, 620)
        self.configure(bg="#0d1117")
        self.resizable(True, True)

        self._apply_theme()
        self._build_ui()
        self._history: list[dict] = self._load_history()
        self._current_result: dict | None = None

        # centre on screen
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - self.winfo_width())  // 2
        y = (self.winfo_screenheight() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    # ─── theme ────────────────────────────────────────────────────

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        BG   = "#0d1117"
        CARD = "#161b22"
        ACC  = "#00d4aa"
        FG   = "#e6edf3"
        SFG  = "#8b949e"
        SEL  = "#1f6feb"

        style.configure(".",            background=BG,   foreground=FG,
                         font=("Consolas", 10))
        style.configure("TFrame",       background=BG)
        style.configure("Card.TFrame",  background=CARD,  relief="flat")
        style.configure("TLabel",       background=BG,   foreground=FG)
        style.configure("Card.TLabel",  background=CARD, foreground=FG)
        style.configure("Sub.TLabel",   background=CARD, foreground=SFG,
                         font=("Consolas", 9))
        style.configure("Accent.TLabel",background=CARD, foreground=ACC,
                         font=("Consolas", 11, "bold"))
        style.configure("TEntry",       fieldbackground="#21262d",
                         foreground=FG, insertcolor=FG,
                         bordercolor="#30363d", lightcolor="#30363d",
                         darkcolor="#30363d")
        style.configure("TButton",      background="#238636", foreground="#ffffff",
                         borderwidth=0, focuscolor="none",
                         font=("Consolas", 10, "bold"), padding=8)
        style.map("TButton",
                  background=[("active", "#2ea043"), ("disabled", "#21262d")],
                  foreground=[("disabled", SFG)])
        style.configure("Danger.TButton", background="#da3633", foreground="#ffffff")
        style.map("Danger.TButton",
                  background=[("active", "#f85149")])
        style.configure("TNotebook",    background=BG,  tabmargins=[0, 0, 0, 0],
                         borderwidth=0)
        style.configure("TNotebook.Tab",background="#21262d", foreground=SFG,
                         padding=[14, 6], borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", FG)])
        style.configure("Treeview",     background=CARD, fieldbackground=CARD,
                         foreground=FG, borderwidth=0, rowheight=24)
        style.configure("Treeview.Heading", background="#21262d", foreground=SFG,
                         borderwidth=0, relief="flat")
        style.map("Treeview", background=[("selected", SEL)])
        style.configure("TScrollbar",   background="#21262d", troughcolor=BG,
                         bordercolor=BG, arrowcolor=SFG)
        style.configure("Horizontal.TSeparator", background="#30363d")

        self._colors = dict(BG=BG, CARD=CARD, ACC=ACC, FG=FG, SFG=SFG)

    # ─── UI construction ──────────────────────────────────────────

    def _build_ui(self):
        C = self._colors

        # ── header bar ───────────────────────────────────────────
        hdr = tk.Frame(self, bg="#161b22", height=60)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🛡  URLHaus Threat Intelligence",
                 bg="#161b22", fg=C["ACC"],
                 font=("Consolas", 16, "bold")).pack(side="left", padx=20, pady=12)

        tk.Label(hdr, text=f"v{APP_VERSION}  |  powered by abuse.ch",
                 bg="#161b22", fg=C["SFG"],
                 font=("Consolas", 9)).pack(side="right", padx=20)

        ttk.Separator(self, orient="horizontal").pack(fill="x")

        # ── input card ───────────────────────────────────────────
        inp = ttk.Frame(self, style="Card.TFrame", padding=16)
        inp.pack(fill="x", padx=16, pady=(12, 0))

        ttk.Label(inp, text="TARGET URL", style="Sub.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 4))

        self._url_var = tk.StringVar()
        self._url_entry = ttk.Entry(inp, textvariable=self._url_var,
                                     font=("Consolas", 12), width=70)
        self._url_entry.grid(row=1, column=0, sticky="ew", padx=(0, 10), ipady=6)
        self._url_entry.bind("<Return>", lambda _: self._run_check())

        self._check_btn = ttk.Button(inp, text="⚡  Analyze Threat",
                                      command=self._run_check)
        self._check_btn.grid(row=1, column=1, sticky="ew", padx=(0, 10))

        self._bulk_btn = ttk.Button(inp, text="📂  Bulk Scan",
                                     command=self._bulk_scan, style="Danger.TButton")
        self._bulk_btn.grid(row=1, column=2, sticky="ew")

        inp.columnconfigure(0, weight=1)

        # progress bar (hidden until scanning)
        self._progress = ttk.Progressbar(inp, mode="indeterminate")
        self._progress.grid(row=2, column=0, columnspan=3, sticky="ew",
                             pady=(10, 0))
        self._progress.grid_remove()

        # ── main notebook ─────────────────────────────────────────
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=16, pady=12)

        self._tab_result  = ttk.Frame(self._nb, style="Card.TFrame")
        self._tab_history = ttk.Frame(self._nb, style="Card.TFrame")
        self._tab_about   = ttk.Frame(self._nb, style="Card.TFrame")

        self._nb.add(self._tab_result,  text="  📊 Analysis Result  ")
        self._nb.add(self._tab_history, text="  📜 Scan History  ")
        self._nb.add(self._tab_about,   text="  ℹ  About  ")

        self._build_result_tab()
        self._build_history_tab()
        self._build_about_tab()

        # ── status bar ───────────────────────────────────────────
        sb = tk.Frame(self, bg="#161b22", height=28)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._status_var = tk.StringVar(value="Ready — enter a URL to begin.")
        tk.Label(sb, textvariable=self._status_var,
                 bg="#161b22", fg=C["SFG"],
                 font=("Consolas", 9), anchor="w").pack(side="left", padx=12, pady=4)

    # ── result tab ────────────────────────────────────────────────

    def _build_result_tab(self):
        C = self._colors
        p = self._tab_result

        # verdict banner
        self._verdict_frame = tk.Frame(p, bg=C["CARD"])
        self._verdict_frame.pack(fill="x", padx=16, pady=(16, 0))

        self._verdict_icon  = tk.Label(self._verdict_frame, text="",
                                        bg=C["CARD"], font=("Segoe UI Emoji", 36))
        self._verdict_icon.pack(side="left", padx=(0, 12))

        vt = tk.Frame(self._verdict_frame, bg=C["CARD"])
        vt.pack(side="left")
        self._verdict_title = tk.Label(vt, text="Awaiting scan…",
                                        bg=C["CARD"], fg=C["FG"],
                                        font=("Consolas", 18, "bold"), anchor="w")
        self._verdict_title.pack(anchor="w")
        self._verdict_sub   = tk.Label(vt, text="Enter a URL and click Analyze.",
                                        bg=C["CARD"], fg=C["SFG"],
                                        font=("Consolas", 10), anchor="w")
        self._verdict_sub.pack(anchor="w")

        ttk.Separator(p, orient="horizontal").pack(fill="x", padx=16, pady=12)

        # metadata grid
        meta = ttk.Frame(p, style="Card.TFrame", padding=(16, 0))
        meta.pack(fill="x")

        def row(frame, label, var, r, c):
            ttk.Label(frame, text=label, style="Sub.TLabel").grid(
                row=r, column=c*2, sticky="nw", padx=(0, 8), pady=4)
            lbl = tk.Label(frame, textvariable=var, bg=C["CARD"], fg=C["FG"],
                            font=("Consolas", 10), anchor="nw", wraplength=340,
                            justify="left")
            lbl.grid(row=r, column=c*2+1, sticky="nw", pady=4, padx=(0, 20))
            return lbl

        self._m = {k: tk.StringVar(value="—") for k in
                   ("url","host","status","threat","tags","added",
                    "reporter","payloads","host_urls","blacklists","reference")}

        pairs_left = [
            ("Queried URL",  "url"),
            ("Host",         "host"),
            ("DB Status",    "status"),
            ("Threat Type",  "threat"),
            ("Tags",         "tags"),
        ]
        pairs_right = [
            ("Date Added",   "added"),
            ("Reporter",     "reporter"),
            ("Payloads",     "payloads"),
            ("URLs on Host", "host_urls"),
            ("Blacklists",   "blacklists"),
        ]

        for r, (lbl, key) in enumerate(pairs_left):
            row(meta, lbl, self._m[key], r, 0)
        for r, (lbl, key) in enumerate(pairs_right):
            row(meta, lbl, self._m[key], r, 1)

        meta.columnconfigure(1, weight=1)
        meta.columnconfigure(3, weight=1)

        # reference link row
        ref_frame = ttk.Frame(p, style="Card.TFrame", padding=(16, 4))
        ref_frame.pack(fill="x")
        ttk.Label(ref_frame, text="URLhaus Reference", style="Sub.TLabel").pack(
            side="left", padx=(0, 8))
        self._ref_link = tk.Label(ref_frame, textvariable=self._m["reference"],
                                   bg=C["CARD"], fg="#58a6ff",
                                   font=("Consolas", 10), cursor="hand2")
        self._ref_link.pack(side="left")
        self._ref_link.bind("<Button-1>", self._open_reference)

        ttk.Separator(p, orient="horizontal").pack(fill="x", padx=16, pady=10)

        # raw JSON viewer
        raw_hdr = ttk.Frame(p, style="Card.TFrame", padding=(16, 0))
        raw_hdr.pack(fill="x")
        ttk.Label(raw_hdr, text="RAW API RESPONSE", style="Sub.TLabel").pack(
            side="left")
        ttk.Button(raw_hdr, text="💾  Export JSON",
                   command=self._export_json).pack(side="right", padx=(0, 4))
        ttk.Button(raw_hdr, text="📋  Export CSV",
                   command=self._export_csv).pack(side="right", padx=(0, 4))

        self._raw_text = scrolledtext.ScrolledText(
            p, height=10, bg="#0d1117", fg=C["FG"],
            font=("Consolas", 9), insertbackground=C["FG"],
            selectbackground="#1f6feb", state="disabled",
            relief="flat", bd=0)
        self._raw_text.pack(fill="both", expand=True, padx=16, pady=(6, 16))

    # ── history tab ───────────────────────────────────────────────

    def _build_history_tab(self):
        C = self._colors
        p = self._tab_history

        ctrl = ttk.Frame(p, style="Card.TFrame", padding=8)
        ctrl.pack(fill="x")
        ttk.Button(ctrl, text="🗑  Clear History",
                   command=self._clear_history, style="Danger.TButton").pack(
            side="right", padx=4)
        ttk.Button(ctrl, text="📋  Export History CSV",
                   command=self._export_history_csv).pack(side="right", padx=4)

        cols = ("timestamp", "url", "found", "status", "threat")
        self._hist_tree = ttk.Treeview(p, columns=cols, show="headings",
                                        selectmode="browse")
        widths = (160, 380, 70, 90, 180)
        hdrs   = ("Timestamp", "URL", "Found", "Status", "Threat")
        for col, hdr, w in zip(cols, hdrs, widths):
            self._hist_tree.heading(col, text=hdr)
            self._hist_tree.column(col,  width=w, anchor="w")

        vsb = ttk.Scrollbar(p, orient="vertical",
                             command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=vsb.set)

        self._hist_tree.pack(side="left", fill="both", expand=True, padx=(16, 0), pady=8)
        vsb.pack(side="right", fill="y", pady=8, padx=(0, 8))

        # tag colours
        self._hist_tree.tag_configure("threat",  foreground="#ff4444")
        self._hist_tree.tag_configure("clean",   foreground="#3fb950")
        self._hist_tree.tag_configure("unknown", foreground="#8b949e")

        self._hist_tree.bind("<<TreeviewSelect>>", self._on_hist_select)

    # ── about tab ─────────────────────────────────────────────────

    def _build_about_tab(self):
        C = self._colors
        p = self._tab_about

        about_text = f"""
  🛡  URLHaus Threat Intelligence Checker  {APP_VERSION}

  ──────────────────────────────────────────────────────────────────────────

  WHAT THIS TOOL DOES
  ───────────────────
  Queries the abuse.ch URLHaus database in real-time to determine whether
  a submitted URL has been reported as a live cyber threat.

  THREAT CATEGORIES DETECTED
  ──────────────────────────
  ⚠  Malware Distribution   – URLs actively serving malware payloads
  🎣  Phishing Pages          – Sites harvesting credentials or PII
  ☠   Command & Control (C2)  – Infrastructure used to control botnets/RATs
  💥  Exploit Kits            – Pages that exploit browser/plugin vulnerabilities
  📧  Spam Infrastructure     – URLs used in spam campaigns

  HOW IT WORKS
  ────────────
  1. You enter a URL (or load a bulk list).
  2. The tool sends a POST request to https://urlhaus-api.abuse.ch/v1/url/
  3. The response is parsed and enriched with host-level intelligence
     from https://urlhaus-api.abuse.ch/v1/host/
  4. Results are displayed and logged to the history tab.

  DATA PRIVACY
  ────────────
  URLs you query are sent to abuse.ch's API. No data is stored by this
  tool beyond your local scan history file (~/.urlhaus_checker_history.json).

  ABOUT URLHaus (abuse.ch)
  ────────────────────────
  URLHaus is a project by abuse.ch with the goal of sharing malicious URLs
  used for malware distribution. It is maintained by a team of security
  researchers and relies on community submissions.
  → https://urlhaus.abuse.ch

  DISCLAIMER
  ──────────
  This tool is intended for defensive security research and threat hunting.
  Use responsibly and in accordance with applicable laws and regulations.
  A "clean" result does not guarantee a URL is safe — the URLHaus database
  only contains confirmed/reported threats.
        """
        txt = scrolledtext.ScrolledText(p, bg=C["CARD"], fg=C["FG"],
                                         font=("Consolas", 10),
                                         state="normal", relief="flat", bd=0)
        txt.insert("end", about_text)
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True, padx=16, pady=16)

    # ─── actions ──────────────────────────────────────────────────

    def _run_check(self, url: str | None = None):
        target = url or self._url_var.get().strip()
        if not target:
            messagebox.showwarning("No URL", "Please enter a URL to analyze.")
            return

        self._check_btn.config(state="disabled")
        self._bulk_btn.config(state="disabled")
        self._progress.grid()
        self._progress.start(10)
        self._set_status(f"Querying URLHaus for: {target}")

        def worker():
            result = query_urlhaus(target)
            self.after(0, lambda: self._show_result(result))

        threading.Thread(target=worker, daemon=True).start()

    def _bulk_scan(self):
        path = filedialog.askopenfilename(
            title="Select URL list (one URL per line)",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"),
                       ("All files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                urls = [ln.strip() for ln in f if ln.strip() and
                        not ln.startswith("#")]
        except Exception as e:
            messagebox.showerror("File Error", str(e))
            return

        if not urls:
            messagebox.showinfo("Empty File", "No URLs found in file.")
            return

        self._check_btn.config(state="disabled")
        self._bulk_btn.config(state="disabled")
        self._progress.grid()
        self._progress.start(10)
        self._set_status(f"Bulk scanning {len(urls)} URLs…")

        def worker():
            results = []
            for i, u in enumerate(urls, 1):
                self.after(0, lambda u=u, i=i:
                    self._set_status(f"Scanning {i}/{len(urls)}: {u}"))
                r = query_urlhaus(u)
                results.append(r)
                self.after(0, lambda r=r: self._record_history(r))

            self.after(0, lambda: self._show_bulk_done(results))

        threading.Thread(target=worker, daemon=True).start()

    def _show_bulk_done(self, results: list):
        self._reset_controls()
        threats = [r for r in results if r["found"]]
        msg = (f"Bulk scan complete.\n\n"
               f"Total scanned : {len(results)}\n"
               f"Threats found : {len(threats)}\n"
               f"Clean / Unknown: {len(results) - len(threats)}\n\n"
               f"Check the History tab for individual results.")
        messagebox.showinfo("Bulk Scan Complete", msg)
        self._nb.select(self._tab_history)
        self._set_status(f"Bulk scan done – {len(threats)} threat(s) found in "
                          f"{len(results)} URL(s).")

    def _show_result(self, result: dict):
        self._reset_controls()
        self._current_result = result
        C = self._colors

        if result.get("error"):
            self._verdict_icon.config(text="🔴")
            self._verdict_title.config(text="Error", fg="#ff4444")
            self._verdict_sub.config(text=result["error"])
            for v in self._m.values():
                v.set("—")
            self._show_raw({"error": result["error"]})
            self._set_status(f"Error: {result['error']}")
            return

        # ── verdict banner ────────────────────────────────────────
        if result["found"]:
            icon  = result.get("threat_icon", "⚠")
            color = result.get("threat_color", "#ff4444")
            label = result.get("threat_label", "Malicious")
            sub   = (f"Status in URLHaus: {result['status'].upper()}  "
                     f"| First seen: {result.get('date_added','—')}")
        else:
            icon, color, label = "✅", "#3fb950", "Not Listed in URLHaus"
            sub = "This URL has no record in the abuse.ch URLHaus database."

        self._verdict_icon.config(text=icon, fg=color)
        self._verdict_title.config(text=label, fg=color)
        self._verdict_sub.config(text=sub)

        # ── metadata fields ───────────────────────────────────────
        self._m["url"].set(result["queried_url"])
        self._m["host"].set(result.get("host") or "—")
        self._m["status"].set(result["status"].upper() if result["status"] else "—")
        self._m["threat"].set(result.get("threat_label") or ("N/A" if not result["found"] else "—"))
        self._m["tags"].set(", ".join(result.get("tags") or []) or "—")
        self._m["added"].set(result.get("date_added") or "—")
        self._m["reporter"].set(result.get("reporter") or "—")

        payloads = result.get("payloads") or []
        if payloads:
            payload_str = "\n".join(
                f"{p.get('file_type','?')} | {p.get('signature','?')} | "
                f"{p.get('virustotal_percent','?')}% VT detection"
                for p in payloads[:5]
            )
        else:
            payload_str = "None recorded"
        self._m["payloads"].set(payload_str)

        hi = result.get("host_info")
        self._m["host_urls"].set(str(hi["urls_on_host"]) if hi else "—")
        if hi and hi.get("blacklists"):
            bl = hi["blacklists"]
            bl_str = "  ".join(f"{k}: {v}" for k, v in bl.items())
            self._m["blacklists"].set(bl_str or "—")
        else:
            self._m["blacklists"].set("—")

        ref = result.get("reference") or "—"
        self._m["reference"].set(ref)

        # ── raw JSON ──────────────────────────────────────────────
        self._show_raw(result.get("raw") or {})

        # ── history ───────────────────────────────────────────────
        self._record_history(result)
        self._nb.select(self._tab_result)

        verb = "THREAT DETECTED" if result["found"] else "Clean (not listed)"
        self._set_status(f"{verb}  |  {result['queried_url']}")

    def _show_raw(self, data: dict):
        txt = json.dumps(data, indent=2, default=str)
        self._raw_text.config(state="normal")
        self._raw_text.delete("1.0", "end")
        self._raw_text.insert("end", txt)
        self._raw_text.config(state="disabled")

    def _record_history(self, result: dict):
        entry = {
            "timestamp": result.get("timestamp", ""),
            "url":       result.get("queried_url", ""),
            "found":     result.get("found", False),
            "status":    result.get("status", ""),
            "threat":    result.get("threat_label") or ("N/A" if not result["found"] else "—"),
            "error":     result.get("error"),
        }
        self._history.insert(0, entry)
        self._history = self._history[:500]   # cap at 500
        self._save_history()
        self._refresh_history_tree()

    def _refresh_history_tree(self):
        self._hist_tree.delete(*self._hist_tree.get_children())
        for e in self._history:
            tag = "threat" if e["found"] else ("unknown" if e.get("error") else "clean")
            self._hist_tree.insert("", "end",
                values=(
                    e["timestamp"][:19].replace("T", " "),
                    e["url"],
                    "YES" if e["found"] else "NO",
                    e["status"].upper() if e.get("status") else "ERROR",
                    e["threat"] or "—",
                ),
                tags=(tag,))

    def _on_hist_select(self, _evt):
        sel = self._hist_tree.selection()
        if not sel:
            return
        idx = self._hist_tree.index(sel[0])
        if idx < len(self._history):
            entry = self._history[idx]
            self._url_var.set(entry["url"])

    def _open_reference(self, _evt):
        ref = self._m["reference"].get()
        if ref and ref.startswith("http"):
            import webbrowser
            webbrowser.open(ref)

    def _reset_controls(self):
        self._check_btn.config(state="normal")
        self._bulk_btn.config(state="normal")
        self._progress.stop()
        self._progress.grid_remove()

    def _set_status(self, msg: str):
        self._status_var.set(f"  {msg}")

    # ─── export ───────────────────────────────────────────────────

    def _export_json(self):
        if not self._current_result:
            messagebox.showinfo("No Data", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"urlhaus_{datetime.date.today()}.json")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._current_result, f, indent=2, default=str)
            messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def _export_csv(self):
        if not self._current_result:
            messagebox.showinfo("No Data", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"urlhaus_{datetime.date.today()}.csv")
        if path:
            r = self._current_result
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Field", "Value"])
                w.writerow(["Queried URL",  r.get("queried_url", "")])
                w.writerow(["Host",         r.get("host", "")])
                w.writerow(["Found",        r.get("found", "")])
                w.writerow(["Status",       r.get("status", "")])
                w.writerow(["Threat Type",  r.get("threat_label", "")])
                w.writerow(["Tags",         ", ".join(r.get("tags") or [])])
                w.writerow(["Date Added",   r.get("date_added", "")])
                w.writerow(["Reporter",     r.get("reporter", "")])
                w.writerow(["Reference",    r.get("reference", "")])
            messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def _export_history_csv(self):
        if not self._history:
            messagebox.showinfo("No History", "No scan history to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"urlhaus_history_{datetime.date.today()}.csv")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["timestamp","url","found",
                                                   "status","threat","error"])
                w.writeheader()
                w.writerows(self._history)
            messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def _clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            self._history = []
            self._save_history()
            self._refresh_history_tree()

    # ─── persistence ──────────────────────────────────────────────

    def _load_history(self) -> list:
        try:
            if os.path.exists(self.HISTORY_FILE):
                with open(self.HISTORY_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                    self.after(100, self._refresh_history_tree)
                    return data
        except Exception:
            pass
        return []

    def _save_history(self):
        try:
            with open(self.HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self._history, f, indent=2)
        except Exception:
            pass


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()