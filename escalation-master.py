#!/usr/bin/env python3
"""
escalation-master.py — SSH-based Linux enumeration and reporting tool.

Features:
 - Robust sudo handling (works without interactive TTY).
 - SUID/SGID binary enumeration and highlighting.
 - World-writable directories sampling.
 - SSH private key discovery (constrained scan with exclusions).
 - JSON + HTML report with quick reference links.
 - Verbose mode for step-by-step progress logging.
"""

import paramiko, json, sys, argparse, time, re, html, os
from urllib.parse import quote_plus
from datetime import datetime

def vlog(enabled, msg):
    if enabled:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")

DEFAULT_CMDS = [
    "id",
    "whoami",
    "hostname",
    "uname -a",
    "cat /etc/os-release || true",
    "uptime",
    "ps aux --no-heading | head -n 40",
    "env",
    "ip a || ifconfig || true",
    "ss -tuln || netstat -tuln || true",
    "cat /etc/passwd",
    "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -perm /6000 -ls 2>/dev/null || true",
    "find / -xdev -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /snap -prune -o -type d -writable -printf '%M %u %g %p\\n' 2>/dev/null | head -n 100 || true",
]

SSH_KEY_CMDS = [
    "ls -la /home/*/.ssh 2>/dev/null || true",
    "ls -la /root/.ssh 2>/dev/null || true",
    r"find / -xdev -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /snap -prune -o -type f \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' -o -name '*_rsa' -o -name '*_ed25519' \) -printf '%M %u %g %p\n' 2>/dev/null | head -n 200",
    r"grep -R --binary-files=without-match -n 'BEGIN OPENSSH PRIVATE KEY' /home /root 2>/dev/null | head -n 200",
    r"grep -R --binary-files=without-match -n 'BEGIN RSA PRIVATE KEY' /home /root 2>/dev/null | head -n 200",
]

INTERESTING_BINS = {
    "bash","sh","dash","ksh",
    "python","python2","python3","perl","ruby","php",
    "nc","ncat","netcat","socat",
    "find","awk","sed","xargs","tar","zip","unzip","less","more","man",
    "vi","vim","nano","ed",
    "systemctl","service","docker","podman","kubectl",
    "rsync","cp","mv","gzip","gunzip","openssl","gdb"
}

SUGGESTIONS = {
                    
    "vim": "Review documentation and notes about shell escapes and external command behavior.",
    "vi": "Check external command invocation and configuration/environment effects.",
    "nano": "Review interactions with external tools and file writes to protected paths.",
    "less": "Check if it can invoke external programs/editors and implications.",
    "more": "Review external command invocation capabilities.",
    "man": "Review how external pagers/editors are invoked.",

    "tar": "Review extended options, hooks, and interactions.",
    "zip": "Check interactions with external utilities and writes to system directories.",
    "unzip": "Review overwrite/write behavior and interactions with external tools.",
    "rsync": "Review script/command invocation and permission preservation.",

    "bash": "Review shell behavior under different privileges, profiles, and environment.",
    "sh": "Check environment handling and profile effects.",
    "dash": "Review non-interactive behavior and environment variable handling.",
    "python": "Review subprocess/os module behavior and execution of external commands.",
    "python2": "Same as python: review execution and imports.",
    "python3": "Same as python: review subprocess/imports details.",
    "perl": "Review execution of external commands and environment influence.",
    "ruby": "Review system command execution and environment considerations.",
    "php": "Review system command functions and security-related options.",

    "nc": "Review I/O redirection and program execution capabilities.",
    "ncat": "Check program invocation and channel redirection.",
    "netcat": "Same as nc; review documentation.",
    "socat": "Review PTY/TTY binding and program execution in pipelines.",

    "systemctl": "Review unit/service management and what can be altered.",
    "service": "Check restartable/modifiable services and impact.",
    "docker": "Review daemon/socket access and consequences of container control.",
    "podman": "Similar to docker: review container/socket access implications.",
    "kubectl": "Check contexts/roles/resources available.",

    "find": "Review invoking external programs during result processing.",
    "awk": "Review executing external commands and file writing capabilities.",
    "sed": "Review running external programs/scripts and writes.",
    "xargs": "Review launching commands from stdin-provided arguments.",
    "openssl": "Review key/file operations and system path access.",
    "gdb": "Review debugger interactions with processes/files.",
    "cp": "Review copying with attribute preservation and overwrites.",
    "mv": "Review moving/replacing files in sensitive directories.",
    "gzip": "Review file impact and interactions with external utilities.",
    "gunzip": "Review overwrite behavior and external tool invocation.",
}

def exec_cmd(ssh, command, timeout=25, get_pty=False, write_stdin=None, verbose=False):
    start = time.time()
    vlog(verbose, f"Running: {command}")
    chan_in, chan_out, chan_err = ssh.exec_command(command, timeout=timeout, get_pty=get_pty)
    if write_stdin is not None:
        chan_in.write(write_stdin + "\n")
        chan_in.flush()
    out = chan_out.read().decode(errors="ignore")
    err = chan_err.read().decode(errors="ignore")
    status = chan_out.channel.recv_exit_status()
    elapsed = time.time() - start
    vlog(verbose, f"Done ({status}) in {elapsed:.2f}s")
    return out.strip(), err.strip(), status

def get_sudo_list(ssh, sudo_pass=None, verbose=False):
                                
    out, err, status = exec_cmd(ssh, "sudo -n -l 2>&1 || true", get_pty=False, verbose=verbose)
    combined = (out + "\n" + err).strip()
    if status == 0 or "may run the following commands" in combined.lower() or "user " in combined.lower():
        return {"out": combined, "err": "", "method": "non-interactive"}
    needs_tty = "a terminal is required" in combined.lower()
    needs_pass = "password is required" in combined.lower() or "password for" in combined.lower() or "incorrect password" in combined.lower()
    if not (needs_tty or needs_pass) and combined:
        return {"out": combined, "err": "", "method": "non-interactive"}

    if sudo_pass:
        cmd = "sudo -k -S -p '' -l"
        out2, err2, status2 = exec_cmd(ssh, cmd, get_pty=True, write_stdin=sudo_pass, verbose=verbose)
        combined2 = (out2 + "\n" + err2).strip()
        if status2 == 0 or combined2:
            return {"out": combined2, "err": "", "method": "stdin-pty"}

    return {"out": "", "err": combined or "failed to obtain sudo -l", "method": "failed"}

def parse_sudo_output(output: str):
    parsed = {"entries": [], "all": False}
    if not output or "not allowed" in output.lower() or "may not run" in output.lower():
        return parsed
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    entry_re = re.compile(r'^\(.*?\)\s*(NOPASSWD:|PASSWD:)?\s*(.*)$', re.I)
    for line in lines:
        if re.search(r'\(ALL(:ALL)?\)\s*(NOPASSWD:)?\s*ALL', line):
            parsed["all"] = True
            parsed["entries"].append({"raw": line, "nopasswd": True, "cmds": ["ALL"]})
            continue
        nop = "NOPASSWD" in line.upper()
        cmds = re.findall(r'(/[\w\-/\.\*]+)', line)
        parsed["entries"].append({"raw": line, "nopasswd": nop, "cmds": cmds or []})
    return parsed

def parse_suid(output: str):
    items = []
    for line in output.splitlines():
        if not line.strip():
            continue
        path = line.split()[-1]
        name = path.split("/")[-1]
        interesting = name in INTERESTING_BINS
        items.append({"path": path, "name": name, "interesting": interesting})
    return items

def analyze(results):
    sudo_raw = results.get("sudo -l (handled)", {}).get("out", "")
    parsed_sudo = parse_sudo_output(sudo_raw)
    suid_raw = results.get("find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -perm /6000 -ls 2>/dev/null || true", {}).get("out", "")
    suids = parse_suid(suid_raw)

    highlights = []
    if parsed_sudo["all"]:
        highlights.append("sudo NOPASSWD: ALL detected.")
    for e in parsed_sudo["entries"]:
        if e["nopasswd"]:
            for cmd in e["cmds"]:
                n = cmd.split("/")[-1]
                if n in INTERESTING_BINS:
                    highlights.append(f"sudo NOPASSWD for {n}.")
    for s in suids:
        if s["interesting"]:
            highlights.append(f"SUID/SGID binary of interest: {s['path']}")

    suggest_names = set()
    for e in parsed_sudo["entries"]:
        for cmd in e["cmds"]:
            suggest_names.add(cmd.split("/")[-1])
    for s in suids:
        suggest_names.add(s["name"])

    suggestions = []
    for name in sorted(suggest_names):
        tip = SUGGESTIONS.get(name)
        if tip:
            suggestions.append({"name": name, "tip": tip})

    ww_out = results.get("find / -xdev -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /snap -prune -o -type d -writable -printf '%M %u %g %p\\n' 2>/dev/null | head -n 100 || true", {}).get("out", "")
    ww_sample = ww_out.splitlines()[:15] if ww_out else []

    ssh_keys = []
    for key in [
        "ls -la /home/*/.ssh 2>/dev/null || true",
        "ls -la /root/.ssh 2>/dev/null || true",
        r"find / -xdev -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /snap -prune -o -type f \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' -o -name '*_rsa' -o -name '*_ed25519' \) -printf '%M %u %g %p\n' 2>/dev/null | head -n 200",
        r"grep -R --binary-files=without-match -n 'BEGIN OPENSSH PRIVATE KEY' /home /root 2>/dev/null | head -n 200",
        r"grep -R --binary-files=without-match -n 'BEGIN RSA PRIVATE KEY' /home /root 2>/dev/null | head -n 200",
    ]:
        out = results.get(key, {}).get("out", "")
        if out:
            for ln in out.splitlines():
                if ln.strip():
                    ssh_keys.append(ln.strip())

    if ssh_keys:
        highlights.append("Potential SSH private keys detected (sample listed).")

    return {
        "sudo": parsed_sudo,
        "suid": suids,
        "highlights": highlights,
        "suggestions": suggestions,
        "world_writable_sample": ww_sample,
        "ssh_keys_sample": ssh_keys[:200],
    }

def gtfobin_link(name): return f"https://gtfobins.github.io/gtfobins/{quote_plus(name)}"
def google_link(name): return f"https://www.google.com/search?q={quote_plus(name + ' privilege escalation')}"
def man_link(name): return f"https://www.google.com/search?q={quote_plus('man ' + name)}"

def make_html(data, outfile, meta):
    html_parts = [f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Escalation Master — {html.escape(meta['host'])}</title>
<style>
body{{font-family:Arial, sans-serif;margin:20px;color:#111}}
h1{{margin:0 0 6px 0}} h2{{color:#1e3a8a;margin:12px 0 6px}}
.card{{border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin:10px 0}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #eee;padding:8px;text-align:left}}
.badge{{display:inline-block;background:#eef2ff;color:#1e40af;padding:4px 8px;border-radius:6px;margin-right:6px;text-decoration:none}}
.high{{color:#b10000;font-weight:700}}
pre{{background:#f9fafb;padding:10px;border-radius:6px;overflow:auto;max-height:260px}}
.small{{color:#6b7280;font-size:12px}}
</style></head><body>"""]

    html_parts.append(f"<h1>Escalation Master — {html.escape(meta['host'])}</h1>")
    html_parts.append(f"<div class='small'>User: <b>{html.escape(meta['user'])}</b> &nbsp;|&nbsp; Time: {html.escape(meta['time'])}</div>")

    html_parts.append("<div class='card'><h2>Quick highlights</h2>")
    highs = data["analysis"].get("highlights") or []
    if highs:
        html_parts.append("<ul>")
        for h in highs:
            html_parts.append(f"<li class='high'>{html.escape(h)}</li>")
        html_parts.append("</ul>")
    else:
        html_parts.append("<div>No immediate highlights.</div>")
    html_parts.append("</div>")

    html_parts.append("<div class='card'><h2>Manual Review Suggestions</h2>")
    sugg = data["analysis"].get("suggestions") or []
    if sugg:
        html_parts.append("<table><thead><tr><th>Tool</th><th>What to review</th><th>Docs</th></tr></thead><tbody>")
        for s in sugg:
            name = html.escape(s["name"])
            tip = html.escape(s["tip"])
            links = f"<a class='badge' target='_blank' href='{gtfobin_link(s['name'])}'>GTFOBins</a>"\
                    f"<a class='badge' target='_blank' href='{man_link(s['name'])}'>man/docs</a>"\
                    f"<a class='badge' target='_blank' href='{google_link(s['name'])}'>Search</a>"
            html_parts.append(f"<tr><td><code>{name}</code></td><td>{tip}</td><td>{links}</td></tr>")
        html_parts.append("</tbody></table>")
    else:
        html_parts.append("<div>No suggestions generated.</div>")
    html_parts.append("</div>")

    html_parts.append("<div class='card'><h2>Parsed sudo -l</h2>")
    sudo = data["analysis"]["sudo"]
    if sudo and sudo.get("entries"):
        html_parts.append("<table><thead><tr><th>Raw entry</th><th>NOPASSWD</th><th>Commands</th><th>Links</th></tr></thead><tbody>")
        for e in sudo["entries"]:
            raw = html.escape(e["raw"])
            nop = "YES" if e["nopasswd"] else "no"
            cmds = e["cmds"]
            cmds_html = "<br>".join(html.escape(c) for c in cmds) if cmds else "-"
            links = ""
            for c in cmds:
                n = c.split("/")[-1]
                links += f"<a class='badge' href='{gtfobin_link(n)}' target='_blank'>GTFOBins</a>"
                links += f"<a class='badge' href='{man_link(n)}' target='_blank'>man/docs</a>"
                links += f"<a class='badge' href='{google_link(n)}' target='_blank'>Search</a>"
            html_parts.append(f"<tr><td><pre>{raw}</pre></td><td>{nop}</td><td>{cmds_html}</td><td>{links}</td></tr>")
        html_parts.append("</tbody></table>")
    else:
        html_parts.append("<div>No sudo entries parsed.</div>")
    html_parts.append("</div>")

    html_parts.append("<div class='card'><h2>SUID/SGID files (scanned dirs)</h2>")
    suid = data["analysis"].get("suid") or []
    if suid:
        html_parts.append("<table><thead><tr><th>Path</th><th>Interesting</th><th>Links</th></tr></thead><tbody>")
        for s in suid[:500]:
            name = s["name"]
            path = html.escape(s["path"])
            mark = "YES" if s["interesting"] else ""
            links = f"<a class='badge' href='{gtfobin_link(name)}' target='_blank'>GTFOBins</a>"\
                    f"<a class='badge' href='{man_link(name)}' target='_blank'>man/docs</a>"\
                    f"<a class='badge' href='{google_link(name)}' target='_blank'>Search</a>"
            html_parts.append(f"<tr><td><code>{path}</code></td><td>{mark}</td><td>{links}</td></tr>")
        html_parts.append("</tbody></table>")
    else:
        html_parts.append("<div>No SUID/SGID files found in scanned dirs.</div>")
    html_parts.append("</div>")

    ww = data["analysis"].get("world_writable_sample") or []
    html_parts.append("<div class='card'><h2>World-writable directories (sample)</h2>")
    if ww:
        html_parts.append("<pre>" + html.escape("\n".join(ww)) + "</pre>")
    else:
        html_parts.append("<div>No sample entries.</div>")
    html_parts.append("</div>")

    keys = data["analysis"].get("ssh_keys_sample") or []
    html_parts.append("<div class='card'><h2>Potential SSH private keys (sample)</h2>")
    if keys:
        html_parts.append("<pre>" + html.escape("\n".join(keys[:200])) + "</pre>")
    else:
        html_parts.append("<div>No candidates found.</div>")
    html_parts.append("</div>")

    html_parts.append("<div class='small'>Report generated by escalation-master.py.</div>")
    html_parts.append("</body></html>")

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))
    return outfile

def connect(host, port, user, password=None, pkey=None, verbose=False):
    vlog(verbose, f"Connecting to {user}@{host}:{port} ...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if pkey:
            key = paramiko.RSAKey.from_private_key_file(pkey)
            ssh.connect(host, port=port, username=user, pkey=key, timeout=10)
        else:
            ssh.connect(host, port=port, username=user, password=password, timeout=10)
    except Exception as e:
        return None, str(e)
    vlog(verbose, "Connected.")
    return ssh, None

def main():
    ap = argparse.ArgumentParser(description="Escalation Master (SSH enumerator)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--port", type=int, default=22)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--password", help="SSH password")
    g.add_argument("--pkey", help="Path to private key for SSH authentication")
    ap.add_argument("--sudo-pass", help="Password to use for 'sudo -l' if non-interactive sudo requires it")
    ap.add_argument("--out", default="escalation_result.json")
    ap.add_argument("--html", default="escalation_report.html")
    ap.add_argument("--verbose", action="store_true", help="Print verbose progress logs")
    args = ap.parse_args()

    ssh, err = connect(args.host, args.port, args.user, args.password, args.pkey, verbose=args.verbose)
    if err:
        sys.exit(f"[!] Connection failed: {err}")

    results = {}
    for cmd in DEFAULT_CMDS:
        try:
            out, err, status = exec_cmd(ssh, cmd, get_pty=False, verbose=args.verbose)
        except Exception as e:
            out, err, status = "", str(e), 1
        results[cmd] = {"out": out, "err": err, "status": status}

    for cmd in SSH_KEY_CMDS:
        try:
            out, err, status = exec_cmd(ssh, cmd, get_pty=False, verbose=args.verbose)
        except Exception as e:
            out, err, status = "", str(e), 1
        results[cmd] = {"out": out, "err": err, "status": status}

    sudo_data = get_sudo_list(ssh, sudo_pass=args.sudo_pass, verbose=args.verbose)
    results["sudo -l (handled)"] = sudo_data

    ssh.close()
    vlog(args.verbose, "SSH session closed. Analyzing results...")

    analysis = analyze(results)
    data = {"results": results, "analysis": analysis}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    vlog(args.verbose, f"Wrote JSON to {args.out}")

    meta = {"host": args.host, "user": args.user, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    make_html(data, args.html, meta)
    vlog(args.verbose, f"Wrote HTML to {args.html}")

    print(f"[+] Results saved to {args.out}")
    print(f"[+] HTML report: {args.html}")
    print("\n--- Highlights ---")
    for h in analysis["highlights"]:
        print(" *", h)
    if not analysis["highlights"]:
        print(" No immediate highlights.")
    print("\n[Info] sudo was handled via:", sudo_data.get("method","unknown"))

if __name__ == "__main__":
    main()
