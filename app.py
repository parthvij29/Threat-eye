import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import os
import signal
import sqlite3
from datetime import datetime


# --- Database Setup ---
def init_database():
    conn = sqlite3.connect('threat_eye_logs.db')
    c = conn.cursor()
    
    # File inspections table
    c.execute('''CREATE TABLE IF NOT EXISTS file_inspections
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  filepath TEXT,
                  result TEXT)''')
    
    # Malicious scans table
    c.execute('''CREATE TABLE IF NOT EXISTS malicious_scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  result TEXT)''')
    
    # Network logs table
    c.execute('''CREATE TABLE IF NOT EXISTS network_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  log_type TEXT,
                  result TEXT)''')
    
    # System logs table
    c.execute('''CREATE TABLE IF NOT EXISTS system_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  log_type TEXT,
                  result TEXT)''')
    
    # Real-time events table
    c.execute('''CREATE TABLE IF NOT EXISTS realtime_events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  event TEXT)''')
    
    # Correlator events table
    c.execute('''CREATE TABLE IF NOT EXISTS correlator_events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  event TEXT,
                  filepath TEXT,
                  pids TEXT,
                  net_pids TEXT,
                  alert INTEGER,
                  summary TEXT)''')
    
    conn.commit()
    conn.close()


def log_to_db(table, data):
    conn = sqlite3.connect('threat_eye_logs.db')
    c = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    
    if table == 'file_inspections':
        c.execute("INSERT INTO file_inspections (timestamp, filepath, result) VALUES (?, ?, ?)",
                 (timestamp, data['filepath'], data['result']))
    elif table == 'malicious_scans':
        c.execute("INSERT INTO malicious_scans (timestamp, result) VALUES (?, ?)",
                 (timestamp, data['result']))
    elif table == 'network_logs':
        c.execute("INSERT INTO network_logs (timestamp, log_type, result) VALUES (?, ?, ?)",
                 (timestamp, data['log_type'], data['result']))
    elif table == 'system_logs':
        c.execute("INSERT INTO system_logs (timestamp, log_type, result) VALUES (?, ?, ?)",
                 (timestamp, data['log_type'], data['result']))
    elif table == 'realtime_events':
        c.execute("INSERT INTO realtime_events (timestamp, event) VALUES (?, ?)",
                 (timestamp, data['event']))
    elif table == 'correlator_events':
        c.execute("INSERT INTO correlator_events (timestamp, event, filepath, pids, net_pids, alert, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (timestamp, data['event'], data['filepath'], data['pids'], data['net_pids'], data['alert'], data['summary']))
    
    conn.commit()
    conn.close()


# --- Helper to run bash scripts and show output ---
def run_script(script, args=None, input_text=None):
    cmd = [script]
    if args:
        if isinstance(args, (list, tuple)):
            cmd += list(map(str, args))
        else:
            cmd.append(str(args))

    try:
        if input_text is not None:
            proc = subprocess.run(cmd, input=input_text, text=True, capture_output=True)
        else:
            proc = subprocess.run(cmd, text=True, capture_output=True)
        output = proc.stdout if proc.stdout else proc.stderr
        return output
    except Exception as e:
        return str(e)


# --- File Inspection ---
def inspect_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        output = run_script("../scripts/file_inspector.sh", args=filepath)
        file_text.delete(1.0, tk.END)
        file_text.insert(tk.END, output)
        # Log to database
        log_to_db('file_inspections', {'filepath': filepath, 'result': output})


def run_malicious_scan():
    output = run_script("../scripts/malicious_scan.sh")
    file_text.delete(1.0, tk.END)
    file_text.insert(tk.END, output)
    # Log to database
    log_to_db('malicious_scans', {'result': output})


# --- Network Monitor ---
def net_monitor(option):
    output = run_script("../scripts/net_monitor.sh", args=option)
    net_text.delete(1.0, tk.END)
    net_text.insert(tk.END, output)
    # Log to database
    log_types = {1: 'connections', 2: 'ports', 3: 'capture'}
    log_type = log_types.get(option, f'option_{option}')
    log_to_db('network_logs', {'log_type': log_type, 'result': output})


# --- System Monitor ---
def sys_monitor(option):
    output = run_script("../scripts/sys_monitor.sh", args=option)
    sys_text.delete(1.0, tk.END)
    sys_text.insert(tk.END, output)
    # Log to database
    log_types = {1: 'processes', 2: 'usage', 3: 'top5', 4: 'startup'}
    log_type = log_types.get(option, f'option_{option}')
    log_to_db('system_logs', {'log_type': log_type, 'result': output})


def show_top5_processes():
    # Get the top 5 lines from sys_monitor (option 3)
    output = run_script("../scripts/sys_monitor.sh", args=3)
    lines = output.splitlines()
    # Clear tree
    for i in top_tree.get_children():
        top_tree.delete(i)

    # Expect header then lines like: PID %CPU CMD
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("[*") or ln.lower().startswith("==="):
            continue
        # skip the title "[*] Top 5..." or header
        if ln.upper().startswith("PID "):
            continue
        parts = ln.split(None, 2)
        if len(parts) >= 3:
            pid, cpu, cmd = parts[0], parts[1], parts[2]
            top_tree.insert('', 'end', values=(pid, cpu, cmd))


def kill_selected_process():
    sel = top_tree.selection()
    if not sel:
        messagebox.showinfo("Stop Process", "Please select a process from the list.")
        return
    pid = top_tree.item(sel[0])['values'][0]
    if not pid:
        return
    if messagebox.askyesno("Confirm", f"Kill process PID {pid}?"):
        out = run_script("/bin/kill", args=["-TERM", pid])
        messagebox.showinfo("Kill result", out or f"Sent TERM to {pid}")
        show_top5_processes()


# --- Real-Time Monitor ---
realtime_process = None


def run_realtime():
    global realtime_process
    if realtime_process and realtime_process.poll() is None:
        realtime_text.insert(tk.END, "\n[!] Already running...\n")
        realtime_text.see(tk.END)
        return

    realtime_process = subprocess.Popen(
        ["../scripts/realtime_monitor.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    def stream_output():
        for line in realtime_process.stdout:
            realtime_text.insert(tk.END, line)
            realtime_text.see(tk.END)
            # Log to database
            log_to_db('realtime_events', {'event': line.strip()})

    threading.Thread(target=stream_output, daemon=True).start()
    realtime_text.insert(tk.END, "[*] Real-Time Monitoring Started...\n")


correlator_process = None


def start_correlator():
    global correlator_process
    if correlator_process and correlator_process.poll() is None:
        realtime_text.insert(tk.END, "\n[!] Correlator already running...\n")
        realtime_text.see(tk.END)
        return

    # Start the correlator script in its own process group so we can terminate group later
    correlator_process = subprocess.Popen(
        ["../scripts/realtime_correlator.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,
    )

    def stream_corr():
        buffer = []
        for raw in correlator_process.stdout:
            line = raw.rstrip('\n')
            # If this is a structured event, parse and insert into the correlator tree
            if line.startswith('CORRELATOR_EVENT'):
                # expected format: CORRELATOR_EVENT\t<ts>\t<event>\t<filepath>\t<pids>\t<net_pids>\t<alert>\t<summary>
                parts = line.split('\t')
                if len(parts) >= 8:
                    _, ts, ev, filepath, pids, net_pids, alert, summary = parts[:8]
                    # Log to database
                    log_to_db('correlator_events', {
                        'event': ev,
                        'filepath': filepath,
                        'pids': pids,
                        'net_pids': net_pids,
                        'alert': int(alert.strip()),
                        'summary': summary
                    })
                    # Insert into UI tree
                    tag = 'alert' if alert.strip() == '1' else ''
                    corr_tree.insert('', 0, values=(ts, ev, filepath, pids, net_pids, summary), tags=(tag,))
                    # Keep tree size bounded
                    if len(corr_tree.get_children()) > 500:
                        # remove oldest
                        cid = corr_tree.get_children()[-1]
                        corr_tree.delete(cid)
                    # update alert counter
                    if alert.strip() == '1':
                        curr = int(alert_count_var.get())
                        alert_count_var.set(str(curr + 1))
                # also append a compact message to realtime_text for context
                realtime_text.insert(tk.END, f"[CORR] {ts} {summary} -> {filepath}\n")
                realtime_text.see(tk.END)
            else:
                # regular output, append to realtime log area
                realtime_text.insert(tk.END, line + "\n")
                realtime_text.see(tk.END)
                # Log to database
                log_to_db('realtime_events', {'event': line})

    threading.Thread(target=stream_corr, daemon=True).start()
    realtime_text.insert(tk.END, "[*] Correlator started...\n")


def stop_correlator():
    global correlator_process
    if correlator_process:
        try:
            # Kill the whole process group started with setsid
            os.killpg(os.getpgid(correlator_process.pid), signal.SIGTERM)
        except Exception:
            try:
                correlator_process.terminate()
            except Exception:
                pass
        correlator_process = None
        realtime_text.insert(tk.END, "\n[!] Correlator stopped.\n")
        realtime_text.see(tk.END)


def stop_realtime():
    global realtime_process
    if realtime_process:
        try:
            realtime_process.terminate()
        except Exception:
            pass
        realtime_process = None
        realtime_text.insert(tk.END, "\n[!] Monitoring stopped.\n")
        realtime_text.see(tk.END)


# --- Main Window ---
root = tk.Tk()
root.title('Threat-Eye - Cyber Defense Console')
root.geometry('1320x820')
root.configure(bg='#111318')
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Initialize database
init_database()

# Style setup
style = ttk.Style(root)
style.theme_use('clam')
style.configure('TButton', background='#10202f', foreground='#e7f6ff', borderwidth=0)
style.map('TButton', background=[('active', '#16314a')])
style.configure('TLabel', background='#09111a', foreground='#e7f6ff')
style.configure('Treeview', background='#0f1723', fieldbackground='#0f1723', foreground='#d7e9ff', rowheight=24, bordercolor='#0f1723', borderwidth=0)
style.map('Treeview', background=[('selected', '#35d7ff')], foreground=[('selected', '#08101b')])

bg_color = '#09111a'
panel_bg = '#0f1827'
card_bg = '#121f33'
accent_cyan = '#35d7ff'
accent_green = '#8cff8e'
accent_pink = '#c96cff'
accent_text = '#d7e9ff'
accent_sub = '#7fa0c2'


class RoundedFrame(tk.Canvas):
    def __init__(self, parent, bg_color=card_bg, radius=20, **kwargs):
        super().__init__(parent, highlightthickness=0, bd=0, bg=parent['bg'], **kwargs)
        self.radius = radius
        self.bg_color = bg_color
        self.frame = tk.Frame(self, bg=bg_color)
        self.window = self.create_window(0, 0, anchor='nw', window=self.frame)
        self.bind('<Configure>', self._resize)

    def _resize(self, event):
        self.delete('bg')
        w, h = event.width, event.height
        r = self.radius
        self.create_rectangle(r, 0, w - r, h, fill=self.bg_color, outline=self.bg_color, tags='bg')
        self.create_rectangle(0, r, w, h - r, fill=self.bg_color, outline=self.bg_color, tags='bg')
        self.create_oval(0, 0, r * 2, r * 2, fill=self.bg_color, outline=self.bg_color, tags='bg')
        self.create_oval(w - r * 2, 0, w, r * 2, fill=self.bg_color, outline=self.bg_color, tags='bg')
        self.create_oval(0, h - r * 2, r * 2, h, fill=self.bg_color, outline=self.bg_color, tags='bg')
        self.create_oval(w - r * 2, h - r * 2, w, h, fill=self.bg_color, outline=self.bg_color, tags='bg')
        self.coords(self.window, 0, 0)
        self.itemconfig(self.window, width=w, height=h)


# Page management helpers
page_frames = {}

def show_page(name):
    frame = page_frames.get(name)
    if frame:
        frame.tkraise()
        header_label.config(text=f'Threat-Eye - {name.replace('_',' ').title()}')


def query_count(table):
    conn = sqlite3.connect('threat_eye_logs.db')
    c = conn.cursor()
    c.execute(f'SELECT COUNT(*) FROM {table}')
    count = c.fetchone()[0]
    conn.close()
    return count


def refresh_dashboard():
    file_count_var.set(query_count('file_inspections'))
    scan_count_var.set(query_count('malicious_scans'))
    network_count_var.set(query_count('network_logs'))
    system_count_var.set(query_count('system_logs'))
    alert_count_var.set(query_count('correlator_events'))
    draw_network_flux(canvas_flux)
    draw_active_assets(canvas_assets, 1248)
    update_terminal_feed()
    update_recent_activity(recent_text)


def update_terminal_feed():
    dashboard_text.delete(1.0, tk.END)
    conn = sqlite3.connect('threat_eye_logs.db')
    c = conn.cursor()
    c.execute('SELECT timestamp, event FROM realtime_events ORDER BY timestamp DESC LIMIT 15')
    for ts, ev in c.fetchall():
        dashboard_text.insert(tk.END, f'[{ts}] {ev}\n')
    conn.close()


def quick_overview():
    run_malicious_scan()
    sys_monitor(2)
    net_monitor(1)
    refresh_dashboard()
    dashboard_text.insert(tk.END, '[DASHBOARD] Quick overview executed.\n')
    dashboard_text.see(tk.END)


def draw_network_flux(canvas):
    canvas.delete('all')
    w = int(canvas.winfo_width() or 760)
    h = int(canvas.winfo_height() or 220)
    canvas.create_rectangle(0, 0, w, h, fill=bg_color, outline='')
    bar_values = [0.24, 0.46, 0.38, 0.60, 0.82, 0.53, 0.48, 0.56, 0.42, 0.50]
    bar_width = (w - 80) / len(bar_values)
    for i, val in enumerate(bar_values):
        x = 40 + i * bar_width
        y = h - 30
        bar_h = val * (h - 80)
        color = accent_cyan if i == 4 else '#32526e'
        canvas.create_rectangle(x, y, x + bar_width * 0.7, y - bar_h, fill=color, outline='')
    canvas.create_text(40, 18, anchor='nw', text='Real-time / 250ms latency', fill=accent_sub, font=('Segoe UI', 8, 'italic'))


def draw_active_assets(canvas, total):
    canvas.delete('all')
    w = int(canvas.winfo_width() or 280)
    h = int(canvas.winfo_height() or 170)
    radius = min(w, h) * 0.32
    cx, cy = w / 2, h / 2
    canvas.create_oval(cx - radius - 10, cy - radius - 10, cx + radius + 10, cy + radius + 10, outline='#18334f', width=12)
    canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, outline=accent_cyan, width=8)
    canvas.create_text(cx, cy - 10, text=str(total), fill=accent_text, font=('Segoe UI', 22, 'bold'))
    canvas.create_text(cx, cy + 22, text='ONLINE', fill=accent_sub, font=('Segoe UI', 9, 'bold'))


def update_recent_activity(widget):
    widget.delete(1.0, tk.END)
    conn = sqlite3.connect('threat_eye_logs.db')
    c = conn.cursor()
    c.execute('SELECT timestamp, event FROM realtime_events ORDER BY timestamp DESC LIMIT 6')
    rows = c.fetchall()
    conn.close()
    if not rows:
        widget.insert(tk.END, 'No recent activity available.\n')
        return
    for ts, ev in rows:
        widget.insert(tk.END, f'[{ts}] {ev}\n')
        widget.insert(tk.END, '-' * 46 + '\n')


def view_logs():
    logs_text.delete(1.0, tk.END)
    table = log_type_var.get()
    conn = sqlite3.connect('threat_eye_logs.db')
    c = conn.cursor()
    if table == 'realtime_events':
        c.execute('SELECT timestamp, event FROM realtime_events ORDER BY timestamp DESC LIMIT 100')
        rows = c.fetchall()
        for ts, event in rows:
            logs_text.insert(tk.END, f'[{ts}] {event}\n')
    elif table == 'correlator_events':
        c.execute('SELECT timestamp, event, filepath, pids, net_pids, alert, summary FROM correlator_events ORDER BY timestamp DESC LIMIT 100')
        rows = c.fetchall()
        for ts, event, filepath, pids, net_pids, alert, summary in rows:
            logs_text.insert(tk.END, f'[{ts}] {event} | Alert:{alert} | {summary}\n File:{filepath} PIDs:{pids} Net:{net_pids}\n\n')
    else:
        c.execute(f'SELECT timestamp, result FROM {table} ORDER BY timestamp DESC LIMIT 100')
        rows = c.fetchall()
        for ts, result in rows:
            logs_text.insert(tk.END, f'[{ts}] {result}\n\n')
    conn.close()


def clear_logs():
    table = log_type_var.get()
    if messagebox.askyesno('Confirm Clear', f'Clear all entries from {table}?'):
        conn = sqlite3.connect('threat_eye_logs.db')
        c = conn.cursor()
        c.execute(f'DELETE FROM {table}')
        conn.commit()
        conn.close()
        logs_text.delete(1.0, tk.END)
        refresh_dashboard()

# Main layout
sidebar = tk.Frame(root, bg='#081623', width=220)
sidebar.grid(row=0, column=0, sticky='ns')
sidebar.grid_propagate(False)

logo = tk.Label(sidebar, text='THREAT-EYE', bg='#0b0f16', fg='#ff9d2f', font=('Segoe UI', 15, 'bold'))
logo.pack(anchor='w', pady=(24, 4), padx=16)
logo_sub = tk.Label(sidebar, text='Cyber Defense Console', bg='#0b0f16', fg='#8a95a4', font=('Segoe UI', 9))
logo_sub.pack(anchor='w', padx=16)

nav_items = [('Dashboard', 'dashboard'), ('Network', 'network'), ('Alerts', 'alerts'), ('System', 'system'), ('Logs', 'logs'), ('Inspect', 'inspect')]
for text, page in nav_items:
    btn = tk.Button(sidebar, text=text, command=lambda p=page: show_page(p), bg='#11161f', fg='#f3f5f8', activebackground='#1f2a3b', bd=0, relief='flat', padx=20, pady=14, anchor='w', font=('Segoe UI', 10, 'bold'))
    btn.pack(fill='x', pady=4, padx=12)

status_panel = tk.Frame(sidebar, bg='#10151d')
status_panel.pack(side='bottom', fill='x', pady=20, padx=12)
status_label_small = tk.Label(status_panel, text='SYSTEM STATUS', bg='#10151d', fg='#8a96a7', font=('Segoe UI', 8, 'bold'))
status_label_small.pack(anchor='w', pady=(10, 2))
status_text = tk.Label(status_panel, text='CRITICAL', bg='#10151d', fg='#ff7d2f', font=('Segoe UI', 12, 'bold'))
status_text.pack(anchor='w', pady=(0, 12))

main_area = tk.Frame(root, bg='#111318')
main_area.grid(row=0, column=1, sticky='nsew')
main_area.grid_rowconfigure(1, weight=1)
main_area.grid_columnconfigure(0, weight=1)

header = tk.Frame(main_area, bg='#121922', height=72)
header.grid(row=0, column=0, sticky='ew')
header.grid_propagate(False)
header_label = tk.Label(header, text='Threat-Eye Command Center', bg='#121922', fg='#f3f5f8', font=('Segoe UI', 18, 'bold'))
header_label.pack(side='left', padx=24)
clock_label = tk.Label(header, bg='#121922', fg='#8a96a7', font=('Segoe UI', 10))
clock_label.pack(side='right', padx=24)

content = tk.Frame(main_area, bg='#111318')
content.grid(row=1, column=0, sticky='nsew')
content.grid_rowconfigure(0, weight=1)
content.grid_columnconfigure(0, weight=1)

for page in ['dashboard', 'network', 'alerts', 'system', 'logs', 'inspect']:
    frame = tk.Frame(content, bg='#111318')
    frame.grid(row=0, column=0, sticky='nsew')
    page_frames[page] = frame

# Dashboard Page
dashboard_frame = page_frames['dashboard']

page_header = RoundedFrame(dashboard_frame, bg_color=panel_bg, height=120)
page_header.pack(fill='x', padx=16, pady=(16, 8))
page_header.frame.grid_columnconfigure(0, weight=1)

brand_block = tk.Frame(page_header.frame, bg=panel_bg)
brand_block.grid(row=0, column=0, sticky='w')
tk.Label(brand_block, text='THREAT-EYE', font=('Segoe UI', 26, 'bold'), bg=panel_bg, fg=accent_cyan).pack(anchor='w')
tk.Label(brand_block, text='SENTINEL PROTOCOL ACTIVE', font=('Segoe UI', 9, 'bold'), bg=panel_bg, fg=accent_green).pack(anchor='w', pady=(6,0))
tk.Label(brand_block, text='Live surveillance · precision sentinel active', font=('Segoe UI', 9), bg=panel_bg, fg=accent_sub).pack(anchor='w', pady=(8,0))

status_chip = tk.Label(page_header.frame, text='ONLINE', font=('Segoe UI', 10, 'bold'), bg=accent_green, fg=bg_color, padx=14, pady=10)
status_chip.grid(row=0, column=1, sticky='e', padx=(0,16))

action_bar = tk.Frame(page_header.frame, bg=panel_bg)
action_bar.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(14, 0))
action_bar.grid_columnconfigure(0, weight=1)
inspect_button = tk.Button(action_bar, text='INSPECT FILE', command=inspect_file, bg=accent_pink, fg=bg_color, bd=0, relief='flat', padx=18, pady=10, font=('Segoe UI', 10, 'bold'))
inspect_button.pack(side='left')
scan_button = tk.Button(action_bar, text='RUN MALWARE SCAN', command=run_malicious_scan, bg=accent_cyan, fg=bg_color, bd=0, relief='flat', padx=18, pady=10, font=('Segoe UI', 10, 'bold'))
scan_button.pack(side='left', padx=10)

body_top = tk.Frame(dashboard_frame, bg=bg_color)
body_top.pack(fill='x', padx=16, pady=(0, 12))

flux_card = RoundedFrame(body_top, bg_color=card_bg, width=820, height=360)
flux_card.pack(side='left', fill='both', expand=True, padx=(0, 8))
flux_card.pack_propagate(False)

tk.Label(flux_card.frame, text='TELEMETRY STREAM', bg=card_bg, fg=accent_sub, font=('Segoe UI', 8, 'bold')).pack(anchor='w', padx=18, pady=(18, 0))
tk.Label(flux_card.frame, text='Network Flux', bg=card_bg, fg=accent_text, font=('Segoe UI', 18, 'bold')).pack(anchor='w', padx=18, pady=(8, 0))

canvas_flux = tk.Canvas(flux_card.frame, bg=bg_color, highlightthickness=0, height=240)
canvas_flux.pack(fill='both', expand=True, padx=18, pady=18)

draw_network_flux(canvas_flux)

flux_footer = tk.Frame(flux_card.frame, bg=card_bg)
flux_footer.pack(fill='x', padx=18, pady=(0, 18))

tk.Label(flux_footer, text='Peak Flux', bg=card_bg, fg=accent_sub, font=('Segoe UI', 8)).pack(side='left')
tk.Label(flux_footer, text='1.8 Gb/s', bg=card_bg, fg=accent_cyan, font=('Segoe UI', 11, 'bold')).pack(side='left', padx=8)
tk.Label(flux_footer, text='Packet Loss 0.002%', bg=card_bg, fg='#ff6f6f', font=('Segoe UI', 8, 'bold')).pack(side='left', padx=24)

side_cards = tk.Frame(body_top, bg=bg_color)
side_cards.pack(side='left', fill='both', expand=False, padx=(8, 0))

asset_card = RoundedFrame(side_cards, bg_color=card_bg, width=320, height=260)
asset_card.pack(fill='x', pady=(0, 8))
asset_card.pack_propagate(False)
tk.Label(asset_card.frame, text='ACTIVE ASSETS', bg=card_bg, fg=accent_sub, font=('Segoe UI', 8, 'bold')).pack(anchor='w', padx=18, pady=(18, 0))
canvas_assets = tk.Canvas(asset_card.frame, bg=bg_color, highlightthickness=0, height=160)
canvas_assets.pack(fill='x', padx=18, pady=18)
draw_active_assets(canvas_assets, 1248)
asset_detail = tk.Frame(asset_card.frame, bg=card_bg)
asset_detail.pack(fill='x', padx=18, pady=(0, 18))
tk.Label(asset_detail, text='Workstations 842', bg=card_bg, fg=accent_text, font=('Segoe UI', 9)).pack(anchor='w')
tk.Label(asset_detail, text='Cloud Nodes 406', bg=card_bg, fg=accent_text, font=('Segoe UI', 9)).pack(anchor='w', pady=(4,0))

threat_card = RoundedFrame(side_cards, bg_color=card_bg, width=320, height=260)
threat_card.pack(fill='x')
threat_card.pack_propagate(False)
tk.Label(threat_card.frame, text='SECURITY POSTURE', bg=card_bg, fg=accent_sub, font=('Segoe UI', 8, 'bold')).pack(anchor='w', padx=18, pady=(18, 0))
tk.Label(threat_card.frame, text='Global Threat Index', bg=card_bg, fg=accent_text, font=('Segoe UI', 18, 'bold')).pack(anchor='w', padx=18, pady=(8, 0))
tk.Label(threat_card.frame, text='14.2 LOW ALERT', bg=card_bg, fg=accent_green, font=('Segoe UI', 22, 'bold')).pack(anchor='w', padx=18, pady=(12, 0))

bar_frame = tk.Frame(threat_card.frame, bg=card_bg)
bar_frame.pack(fill='x', padx=18, pady=(16, 8))
for width, color in [(50, '#7cff65'), (60, '#5fd3ff'), (70, '#b28dfd'), (90, '#ff6fb0')]:
    bar_bg = tk.Frame(bar_frame, bg='#0b1420', width=60, height=12)
    bar_bg.pack(side='left', padx=4)
    bar_fg = tk.Frame(bar_bg, bg=color, width=width, height=12)
    bar_fg.place(x=0, y=0)

tk.Label(threat_card.frame, text='All systems operating within normal parameters.', bg=card_bg, fg=accent_sub, font=('Segoe UI', 8)).pack(anchor='w', padx=18, pady=(8, 0))
tk.Label(threat_card.frame, text='Perimeter integrity at 99.8%', bg=card_bg, fg=accent_sub, font=('Segoe UI', 8)).pack(anchor='w', padx=18, pady=(4, 18))

activity_card = RoundedFrame(dashboard_frame, bg_color=card_bg, height=320)
activity_card.pack(fill='both', expand=True, padx=16, pady=(0, 16))

tk.Label(activity_card.frame, text='RECENT ACTIVITY', bg=card_bg, fg=accent_text, font=('Segoe UI', 11, 'bold')).pack(anchor='w', padx=18, pady=(18, 0))
recent_text = scrolledtext.ScrolledText(activity_card.frame, wrap=tk.WORD, bg=bg_color, fg=accent_text, insertbackground=accent_text, borderwidth=0, height=12)
recent_text.pack(fill='both', expand=True, padx=18, pady=(12, 18))
update_recent_activity(recent_text)

footer_row = tk.Frame(dashboard_frame, bg=bg_color)
footer_row.pack(fill='x', padx=16, pady=(0, 16))
for label, value in [('Core Load', '12% / 64 Cores'), ('Uptime', '482 Days / 14h'), ('Shield Level', 'Tier 5 (Maximum)'), ('Global Sync', 'Synchronized')]:
    metric_card = tk.Frame(footer_row, bg=card_bg)
    metric_card.pack(side='left', fill='x', expand=True, padx=6, pady=0)
    tk.Label(metric_card, text=label, bg=card_bg, fg=accent_sub, font=('Segoe UI', 8)).pack(anchor='w', padx=14, pady=(12, 2))
    tk.Label(metric_card, text=value, bg=card_bg, fg=accent_text, font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=14, pady=(0, 12))

terminal_panel = RoundedFrame(dashboard_frame, bg_color=card_bg, height=280)
terminal_panel.pack(fill='both', expand=True, padx=16, pady=(0, 16))

tk.Label(terminal_panel.frame, text='TERMINAL FEED', bg=card_bg, fg=accent_text, font=('Segoe UI', 11, 'bold')).pack(anchor='nw', padx=16, pady=12)
dashboard_text = scrolledtext.ScrolledText(terminal_panel.frame, wrap=tk.WORD, bg=bg_color, fg=accent_text, insertbackground=accent_text, borderwidth=0)
dashboard_text.pack(fill='both', expand=True, padx=16, pady=(0, 16))
dashboard_text.insert(tk.END, 'SYSTEM ONLINE - monitoring dashboard ready.\n')

file_count_var = tk.StringVar(value='0')
scan_count_var = tk.StringVar(value='0')
network_count_var = tk.StringVar(value='0')
system_count_var = tk.StringVar(value='0')
alert_count_var = tk.StringVar(value='0')

# Network Page
network_frame = page_frames['network']

network_controls = tk.Frame(network_frame, bg='#111318')
network_controls.pack(fill='x', padx=16, pady=16)
btn_conn = tk.Button(network_controls, text='Active Connections', command=lambda: net_monitor(1), bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_conn.pack(side='left', padx=6)
btn_ports = tk.Button(network_controls, text='Open Ports', command=lambda: net_monitor(2), bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_ports.pack(side='left', padx=6)
btn_cap = tk.Button(network_controls, text='Capture Packets', command=lambda: net_monitor(3), bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_cap.pack(side='left', padx=6)

net_text = scrolledtext.ScrolledText(network_frame, wrap=tk.WORD, bg='#0b0f14', fg='#eef2f7', insertbackground='#eef2f7', borderwidth=0)
net_text.pack(fill='both', expand=True, padx=16, pady=(0, 16))

# Alerts Page
alerts_frame = page_frames['alerts']

alerts_controls = tk.Frame(alerts_frame, bg='#111318')
alerts_controls.pack(fill='x', padx=16, pady=16)
btn_start = tk.Button(alerts_controls, text='Start Monitoring', command=run_realtime, bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_start.pack(side='left', padx=6)
btn_stop = tk.Button(alerts_controls, text='Stop Monitoring', command=stop_realtime, bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_stop.pack(side='left', padx=6)
btn_start_corr = tk.Button(alerts_controls, text='Start Correlator', command=start_correlator, bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_start_corr.pack(side='left', padx=6)
btn_stop_corr = tk.Button(alerts_controls, text='Stop Correlator', command=stop_correlator, bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_stop_corr.pack(side='left', padx=6)

alerts_body = tk.Frame(alerts_frame, bg='#111318')
alerts_body.pack(fill='both', expand=True, padx=16, pady=(0,16))
alerts_body.grid_columnconfigure(0, weight=1)
alerts_body.grid_columnconfigure(1, weight=1)
alerts_body.grid_rowconfigure(0, weight=1)

realtime_text = scrolledtext.ScrolledText(alerts_body, wrap=tk.WORD, bg='#0b0f14', fg='#eef2f7', insertbackground='#eef2f7', borderwidth=0)
realtime_text.grid(row=0, column=0, sticky='nsew', padx=(0,8))

alert_panel = tk.Frame(alerts_body, bg='#181f29')
alert_panel.grid(row=0, column=1, sticky='nsew', padx=(8,0))
alert_panel.grid_rowconfigure(1, weight=1)

alert_heading = tk.Label(alert_panel, text='CORRELATOR EVENTS', bg='#181f29', fg='#eef2f7', font=('Segoe UI', 11, 'bold'))
alert_heading.pack(anchor='nw', padx=16, pady=12)

alert_badge = tk.Label(alert_panel, textvariable=alert_count_var, bg='#181f29', fg='#ff6f6f', font=('Segoe UI', 22, 'bold'))
alert_badge.pack(anchor='nw', padx=16, pady=(0, 8))

cols_corr = ('Time', 'Event', 'File', 'PIDs', 'Net PIDs', 'Summary')
corr_tree = ttk.Treeview(alert_panel, columns=cols_corr, show='headings', height=12)
for c in cols_corr:
    corr_tree.heading(c, text=c)
    corr_tree.column(c, width=120 if c not in ('File','Summary') else 220)
corr_tree.pack(fill='both', expand=True, padx=16, pady=(0,16))
corr_tree.tag_configure('alert', background='#3b1010')

# System Page
system_frame = page_frames['system']
frame_sys_tools = tk.Frame(system_frame, bg='#111318')
frame_sys_tools.pack(fill='x', padx=16, pady=16)
btn_proc = tk.Button(frame_sys_tools, text='Processes', command=lambda: sys_monitor(1), bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_proc.pack(side='left', padx=6)
btn_usage = tk.Button(frame_sys_tools, text='CPU / Memory', command=lambda: sys_monitor(2), bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_usage.pack(side='left', padx=6)
btn_top = tk.Button(frame_sys_tools, text='Top 5', command=show_top5_processes, bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_top.pack(side='left', padx=6)
btn_startup = tk.Button(frame_sys_tools, text='Startup Services', command=lambda: sys_monitor(4), bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_startup.pack(side='left', padx=6)

sys_text = scrolledtext.ScrolledText(system_frame, wrap=tk.WORD, bg='#0b0f14', fg='#eef2f7', insertbackground='#eef2f7', borderwidth=0, height=10)
sys_text.pack(fill='both', padx=16, pady=(0, 12), expand=True)

process_frame = tk.Frame(system_frame, bg='#181f29')
process_frame.pack(fill='both', padx=16, pady=(0, 16), expand=True)
cols = ('PID','%CPU','CMD')
top_tree = ttk.Treeview(process_frame, columns=cols, show='headings', height=7)
for c in cols:
    top_tree.heading(c, text=c)
    top_tree.column(c, width=130 if c != 'CMD' else 430)
top_tree.pack(fill='both', expand=True, padx=16, pady=(16, 8))

sys_action_frame = tk.Frame(process_frame, bg='#181f29')
sys_action_frame.pack(fill='x', padx=16, pady=(0, 16))
btn_kill = tk.Button(sys_action_frame, text='Kill Process', command=kill_selected_process, bg='#ff5b5b', fg='white', bd=0, padx=16, pady=10)
btn_kill.pack(side='left')
btn_refresh_top = tk.Button(sys_action_frame, text='Refresh Top 5', command=show_top5_processes, bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=10)
btn_refresh_top.pack(side='left', padx=10)

# Logs Page
logs_frame = page_frames['logs']
frame_logs_top = tk.Frame(logs_frame, bg='#111318')
frame_logs_top.pack(fill='x', padx=16, pady=16)

log_type_var = tk.StringVar(value='file_inspections')
log_options = ['file_inspections','malicious_scans','network_logs','system_logs','realtime_events','correlator_events']
log_combo = ttk.Combobox(frame_logs_top, textvariable=log_type_var, values=log_options, state='readonly', width=24)
log_combo.pack(side='left', padx=8)
btn_view = tk.Button(frame_logs_top, text='VIEW LOGS', command=lambda: view_logs(), bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=10)
btn_view.pack(side='left', padx=8)
btn_clear = tk.Button(frame_logs_top, text='CLEAR LOGS', command=lambda: clear_logs(), bg='#ff5b5b', fg='white', bd=0, padx=16, pady=10)
btn_clear.pack(side='left', padx=8)

logs_text = scrolledtext.ScrolledText(logs_frame, wrap=tk.WORD, bg='#0b0f14', fg='#eef2f7', insertbackground='#eef2f7', borderwidth=0)
logs_text.pack(fill='both', expand=True, padx=16, pady=(0,16))

inspect_frame = page_frames['inspect']
inspect_top = tk.Frame(inspect_frame, bg='#111318')
inspect_top.pack(fill='x', padx=16, pady=16)
btn_inspect = tk.Button(inspect_top, text='SELECT FILE FOR INSPECTION', command=inspect_file, bg='#1f242f', fg='#eef2f7', bd=0, padx=16, pady=12)
btn_inspect.pack(side='left', padx=6)
btn_malware = tk.Button(inspect_top, text='RUN MALWARE SCAN', command=run_malicious_scan, bg='#ff5b5b', fg='white', bd=0, padx=16, pady=12)
btn_malware.pack(side='left', padx=6)

file_text = scrolledtext.ScrolledText(inspect_frame, wrap=tk.WORD, bg='#0b0f14', fg='#eef2f7', insertbackground='#eef2f7', borderwidth=0)
file_text.pack(fill='both', expand=True, padx=16, pady=(0,16))

show_page('dashboard')
refresh_dashboard()
root.mainloop()

