import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import os
import signal

# ---------------- Helper ----------------
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
        return proc.stdout if proc.stdout else proc.stderr
    except Exception as e:
        return str(e)


# ---------------- File Inspector ----------------
def inspect_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        output = run_script("../scripts/file_inspector.sh", args=filepath)
        file_text.delete(1.0, tk.END)
        file_text.insert(tk.END, output)


def run_malicious_scan():
    output = run_script("../scripts/malicious_scan.sh")
    file_text.delete(1.0, tk.END)
    file_text.insert(tk.END, output)


# ---------------- Network Monitor ----------------
def net_monitor(option):
    output = run_script("../scripts/net_monitor.sh", args=option)
    net_text.delete(1.0, tk.END)
    net_text.insert(tk.END, output)


# ---------------- System Monitor ----------------
def sys_monitor(option):
    output = run_script("../scripts/sys_monitor.sh", args=option)
    sys_text.delete(1.0, tk.END)
    sys_text.insert(tk.END, output)


def show_top5_processes():
    output = run_script("../scripts/sys_monitor.sh", args=3)
    lines = output.splitlines()

    for i in top_tree.get_children():
        top_tree.delete(i)

    for ln in lines:
        ln = ln.strip()
        if not ln or ln.upper().startswith("PID"):
            continue

        parts = ln.split(None, 2)
        if len(parts) >= 3:
            pid, cpu, cmd = parts
            top_tree.insert('', 'end', values=(pid, cpu, cmd))


def kill_selected_process():
    sel = top_tree.selection()
    if not sel:
        messagebox.showinfo("Stop Process", "Select a process first.")
        return

    pid = top_tree.item(sel[0])['values'][0]

    if messagebox.askyesno("Confirm", f"Kill process PID {pid}?"):
        run_script("/bin/kill", args=["-TERM", pid])
        show_top5_processes()


# ---------------- Real-time Monitor ----------------
realtime_process = None

def run_realtime():
    global realtime_process

    if realtime_process and realtime_process.poll() is None:
        return

    realtime_process = subprocess.Popen(
        ["../scripts/realtime_monitor.sh"],
        stdout=subprocess.PIPE,
        text=True
    )

    def stream():
        for line in realtime_process.stdout:
            realtime_text.insert(tk.END, line)
            realtime_text.see(tk.END)

    threading.Thread(target=stream, daemon=True).start()


def stop_realtime():
    global realtime_process
    if realtime_process:
        realtime_process.terminate()
        realtime_process = None


# ---------------- Correlator ----------------
correlator_process = None

def start_correlator():
    global correlator_process

    correlator_process = subprocess.Popen(
        ["../scripts/realtime_correlator.sh"],
        stdout=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid
    )

    def stream():
        for line in correlator_process.stdout:
            realtime_text.insert(tk.END, line)
            realtime_text.see(tk.END)

    threading.Thread(target=stream, daemon=True).start()


def stop_correlator():
    global correlator_process
    if correlator_process:
        os.killpg(os.getpgid(correlator_process.pid), signal.SIGTERM)
        correlator_process = None


# ================= UI =================
root = tk.Tk()
root.title("Deep Inspector - Linux Monitoring Tool")
root.geometry("1200x750")
root.configure(bg="#1e1e1e")

# ---------- Style ----------
style = ttk.Style()
style.theme_use("clam")

style.configure("TFrame", background="#1e1e1e")
style.configure("TLabel", background="#1e1e1e", foreground="white")
style.configure("TNotebook.Tab", padding=[12,5])

style.configure(
    "Treeview",
    background="#2b2b2b",
    foreground="white",
    fieldbackground="#2b2b2b",
    rowheight=25
)

style.map("Treeview", background=[("selected","#0078D7")])

# ---------- Title ----------
title = tk.Label(
    root,
    text="Deep Inspector - Linux Monitoring Tool",
    font=("Segoe UI",16,"bold"),
    fg="#00ffc6",
    bg="#1e1e1e"
)
title.pack(pady=10)

# ---------- Tabs ----------
tabControl = ttk.Notebook(root)

# ================= FILE TAB =================
file_tab = ttk.Frame(tabControl)
tabControl.add(file_tab, text="File Inspector")

frame = tk.Frame(file_tab, bg="#1e1e1e")
frame.pack(pady=10)

btn_file = tk.Button(frame,text="Inspect File",command=inspect_file,bg="#0078D7",fg="white")
btn_file.grid(row=0,column=0,padx=10)

btn_scan = tk.Button(frame,text="Run Malicious Scan",command=run_malicious_scan,bg="#0078D7",fg="white")
btn_scan.grid(row=0,column=1,padx=10)

file_text = scrolledtext.ScrolledText(file_tab,width=120,height=35,bg="#111",fg="#00ff9c",font=("Consolas",10))
file_text.pack(padx=10,pady=10,fill="both",expand=True)

# ================= NETWORK TAB =================
net_tab = ttk.Frame(tabControl)
tabControl.add(net_tab,text="Network Monitor")

frame = tk.Frame(net_tab,bg="#1e1e1e")
frame.pack(pady=10)

tk.Button(frame,text="Active Connections",command=lambda:net_monitor(1),bg="#0078D7",fg="white").grid(row=0,column=0,padx=8)
tk.Button(frame,text="Open Ports",command=lambda:net_monitor(2),bg="#0078D7",fg="white").grid(row=0,column=1,padx=8)
tk.Button(frame,text="Capture Packets",command=lambda:net_monitor(3),bg="#0078D7",fg="white").grid(row=0,column=2,padx=8)

net_text = scrolledtext.ScrolledText(net_tab,width=120,height=35,bg="#111",fg="#00ff9c",font=("Consolas",10))
net_text.pack(padx=10,pady=10,fill="both",expand=True)

# ================= SYSTEM TAB =================
sys_tab = ttk.Frame(tabControl)
tabControl.add(sys_tab,text="System Monitor")

frame = tk.Frame(sys_tab,bg="#1e1e1e")
frame.pack(pady=8)

tk.Button(frame,text="Running Processes",command=lambda:sys_monitor(1),bg="#0078D7",fg="white").grid(row=0,column=0,padx=5)
tk.Button(frame,text="CPU & Memory",command=lambda:sys_monitor(2),bg="#0078D7",fg="white").grid(row=0,column=1,padx=5)
tk.Button(frame,text="Top 5 by CPU",command=show_top5_processes,bg="#0078D7",fg="white").grid(row=0,column=2,padx=5)
tk.Button(frame,text="Startup Services",command=lambda:sys_monitor(4),bg="#0078D7",fg="white").grid(row=0,column=3,padx=5)

sys_text = scrolledtext.ScrolledText(sys_tab,width=80,height=10,bg="#111",fg="#00ff9c",font=("Consolas",10))
sys_text.pack(pady=6)

cols=("PID","%CPU","CMD")
top_tree = ttk.Treeview(sys_tab,columns=cols,show='headings',height=6)
for c in cols:
    top_tree.heading(c,text=c)

top_tree.column("PID",width=80,anchor="center")
top_tree.column("%CPU",width=80,anchor="center")
top_tree.column("CMD",width=700)

top_tree.pack(pady=6)

btn_frame=tk.Frame(sys_tab,bg="#1e1e1e")
btn_frame.pack()

tk.Button(btn_frame,text="Stop Selected Process",command=kill_selected_process,bg="#C42B1C",fg="white").grid(row=0,column=0,padx=10)
tk.Button(btn_frame,text="Refresh Top 5",command=show_top5_processes,bg="#0078D7",fg="white").grid(row=0,column=1,padx=10)

# ================= REALTIME TAB =================
realtime_tab=ttk.Frame(tabControl)
tabControl.add(realtime_tab,text="Real-Time Monitor")

frame=tk.Frame(realtime_tab,bg="#1e1e1e")
frame.pack(pady=10)

tk.Button(frame,text="Start Monitoring",command=run_realtime,bg="#107C10",fg="white").grid(row=0,column=0,padx=8)
tk.Button(frame,text="Stop Monitoring",command=stop_realtime,bg="#C42B1C",fg="white").grid(row=0,column=1,padx=8)
tk.Button(frame,text="Start Correlator",command=start_correlator,bg="#0078D7",fg="white").grid(row=0,column=2,padx=8)
tk.Button(frame,text="Stop Correlator",command=stop_correlator,bg="#C42B1C",fg="white").grid(row=0,column=3,padx=8)

realtime_text=scrolledtext.ScrolledText(realtime_tab,width=100,height=30,bg="#111",fg="#00ff9c",font=("Consolas",10))
realtime_text.pack(padx=10,pady=10,fill="both",expand=True)

# ================= CORRELATOR TAB =================
corr_tab=ttk.Frame(tabControl)
tabControl.add(corr_tab,text="Correlator")

cols=("Time","Event","File","PIDs","Net PIDs","Summary")
corr_tree=ttk.Treeview(corr_tab,columns=cols,show='headings',height=15)

for c in cols:
    corr_tree.heading(c,text=c)

corr_tree.column("File",width=350)
corr_tree.column("Summary",width=350)

corr_tree.pack(fill="both",expand=True,padx=10,pady=10)

corr_tree.tag_configure("alert",background="#3b0b0b",foreground="#ff4d4d")

# ---------- Start ----------
tabControl.pack(expand=1,fill="both")

root.mainloop()
