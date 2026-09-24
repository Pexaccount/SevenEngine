# -*- coding: utf-8 -*-
"""Analyze spot-test raw results -> stats.json for the HTML report."""
import os, json, statistics, re
BASE = os.path.dirname(os.path.abspath(__file__))

rows = []
with open(os.path.join(BASE, "_spot_raw_v2.jsonl"), encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

def engine_tag(result):
    if result is None:
        return "ERROR"
    # MALICIOUS|family|TAG|conf  /  CLEAN|LightGBM-White  /  CLEAN  /  WHITELIST
    parts = result.split("|")
    if parts[0] == "MALICIOUS":
        return parts[2] if len(parts) >= 4 else "?"
    if len(parts) >= 2:
        return parts[1]
    return parts[0]

def fam(result):
    parts = (result or "").split("|")
    return parts[1] if parts[0] == "MALICIOUS" and len(parts) >= 4 else None

stats = {"groups": {}, "overall": {}, "detect": {}, "white": {}, "latency": {},
         "engine_mix": {}, "conf_hist": {}, "by_family": {}, "missed": [], "fps": []}

# ---------- per-group counts ----------
g = {}
for r in rows:
    grp = r["group"]
    d = g.setdefault(grp, {"total": 0, "error": 0, "mal": 0, "clean": 0, "wl": 0,
                           "secs": [], "engines": {}})
    d["total"] += 1
    if r["err"] or r["result"] is None:
        d["error"] += 1
        continue
    tag = engine_tag(r["result"])
    if r["result"].startswith("MALICIOUS"):
        d["mal"] += 1
    elif r["result"] == "WHITELIST":
        d["wl"] += 1
    else:
        d["clean"] += 1
    d["secs"].append(r["sec"])
    d["engines"][tag] = d["engines"].get(tag, 0) + 1

for grp, d in g.items():
    scanned = d["total"] - d["error"]
    stats["groups"][grp] = {
        "total": d["total"], "scanned": scanned, "error": d["error"],
        "scan_rate": round(scanned / d["total"] * 100, 2) if d["total"] else 0,
        "mal": d["mal"], "clean": d["clean"], "wl": d["wl"],
        "det_rate": round(d["mal"] / scanned * 100, 2) if scanned and grp.startswith("virus_pe") or grp == "virus_script" else None,
        "mean_sec": round(statistics.mean(d["secs"]), 3) if d["secs"] else None,
        "med_sec": round(statistics.median(d["secs"]), 3) if d["secs"] else None,
        "p95_sec": round(sorted(d["secs"])[int(len(d["secs"]) * 0.95)] if len(d["secs"]) > 1 else d["secs"][0], 3) if d["secs"] else None,
        "max_sec": round(max(d["secs"]), 3) if d["secs"] else None,
        "engines": d["engines"],
    }

# ---------- headline metrics ----------
vp = stats["groups"].get("virus_pe", {})
vs = stats["groups"].get("virus_script", {})
wf = stats["groups"].get("white_pf", {})
wx = stats["groups"].get("white_pf_x86", {})
ws = stats["groups"].get("white_sys", {})
virus_scanned = vp.get("scanned", 0) + vs.get("scanned", 0)
virus_mal = vp.get("mal", 0) + vs.get("mal", 0)
white_scanned = wf.get("scanned", 0) + wx.get("scanned", 0) + ws.get("scanned", 0)
white_mal = wf.get("mal", 0) + wx.get("mal", 0) + ws.get("mal", 0)
total_all = sum(d["total"] for d in g.values())
err_all = sum(d["error"] for d in g.values())
scan_secs = [r["sec"] for r in rows if not r["err"] and r["result"] is not None]

# 95% Wilson CI for FPR
import math as _math
def wilson(k, n, z=1.96):
    if n == 0:
        return None, None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * _math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h
fpr_lo, fpr_hi = wilson(white_mal, white_scanned)
det_lo, det_hi = wilson(virus_mal, virus_scanned)

stats["overall"] = {
    "total_sampled": total_all,
    "total_scanned": total_all - err_all,
    "total_error": err_all,
    "scan_rate": round((total_all - err_all) / total_all * 100, 2) if total_all else 0,
    "virus_sampled": vp.get("total", 0) + vs.get("total", 0),
    "virus_scanned": virus_scanned,
    "detection_rate": round(virus_mal / virus_scanned * 100, 2) if virus_scanned else 0,
    "white_sampled": white_scanned,
    "false_positives": white_mal,
    "fpr": round(white_mal / white_scanned * 100, 2) if white_scanned else 0,
    "fpr_ci95": [round(fpr_lo * 100, 2), round(fpr_hi * 100, 2)] if fpr_lo is not None else None,
    "det_ci95": [round(det_lo * 100, 2), round(det_hi * 100, 2)] if det_lo is not None else None,
    "mean_sec": round(statistics.mean(scan_secs), 3) if scan_secs else 0,
    "med_sec": round(statistics.median(scan_secs), 3) if scan_secs else 0,
    "p95_sec": round(sorted(scan_secs)[int(len(scan_secs) * 0.95)], 3) if len(scan_secs) > 1 else 0,
    "throughput_fpm": round(len(scan_secs) / sum(scan_secs) * 60, 1) if scan_secs else 0,
}

# ---------- engine mix (detections) ----------
mix = {}
for r in rows:
    if r["result"] and r["result"].startswith("MALICIOUS"):
        mix[engine_tag(r["result"])] = mix.get(engine_tag(r["result"]), 0) + 1
stats["engine_mix"] = dict(sorted(mix.items(), key=lambda kv: -kv[1]))

# also engine mix for CLEAN white outcomes (which path cleared them)
wmix = {}
for r in rows:
    if r["group"].startswith("white") and r["result"] and not r["result"].startswith("MALICIOUS"):
        t = engine_tag(r["result"])
        wmix[t] = wmix.get(t, 0) + 1
stats["white_engine_mix"] = dict(sorted(wmix.items(), key=lambda kv: -kv[1]))

# ---------- confidence histogram of detections ----------
hist = {f"{i*10}-{i*10+9}": 0 for i in range(10)}
for r in rows:
    if r["result"] and r["result"].startswith("MALICIOUS"):
        c = max(0, min(99, int(r["conf"])))
        hist[f"{(c//10)*10}-{(c//10)*10+9}"] += 1
stats["conf_hist"] = hist

# ---------- by family (virus top folders) ----------
bf = {}
for r in rows:
    if r["group"] not in ("virus_pe", "virus_script"):
        continue
    d = bf.setdefault(r["family"], {"n": 0, "det": 0})
    d["n"] += 1
    if r["result"] and r["result"].startswith("MALICIOUS"):
        d["det"] += 1
stats["by_family"] = {k: {"n": v["n"], "det": v["det"],
                          "rate": round(v["det"] / v["n"] * 100, 1)}
                      for k, v in sorted(bf.items(), key=lambda kv: -kv[1]["n"])}

# ---------- missed / FP lists ----------
for r in rows:
    if r["group"] in ("virus_pe", "virus_script") and not (r["result"] and r["result"].startswith("MALICIOUS")):
        stats["missed"].append({"path": r["path"], "family": r["family"],
                                "result": r["result"], "err": r["err"], "sec": r["sec"]})
    if r["group"].startswith("white") and r["result"] and r["result"].startswith("MALICIOUS"):
        stats["fps"].append({"path": r["path"], "group": r["group"],
                             "result": r["result"], "conf": r["conf"], "sec": r["sec"]})
stats["missed"] = stats["missed"][:200]

# white per-app FPR + Git split (computed from full raw, no truncation)
from collections import Counter
per_app = {}
git = {"n": 0, "fp": 0}
for r in rows:
    if not r["group"].startswith("white"):
        continue
    parts = r["path"].replace("/", "\\").split("\\")
    app = parts[2] if len(parts) > 3 else "(root)"
    d = per_app.setdefault(app, [0, 0])
    d[0] += 1
    is_mal = bool(r["result"] and r["result"].startswith("MALICIOUS"))
    if is_mal:
        d[1] += 1
    if app == "Git":
        git["n"] += 1
        git["fp"] += 1 if is_mal else 0
stats["white_per_app"] = [
    {"app": k, "n": v[0], "fp": v[1], "fpr": round(v[1] / v[0] * 100, 1)}
    for k, v in sorted(per_app.items(), key=lambda kv: -kv[1][1])
]
ng_n = sum(v[0] for v in per_app.values()) - git["n"]
ng_fp = sum(v[1] for v in per_app.values()) - git["fp"]
stats["git_split"] = {
    "git": {"n": git["n"], "fp": git["fp"], "fpr": round(git["fp"] / max(1, git["n"]) * 100, 2)},
    "nongit": {"n": ng_n, "fp": ng_fp, "fpr": round(ng_fp / max(1, ng_n) * 100, 2)},
}

# ---------- verdict distribution ----------
vd = {}
for r in rows:
    if r["err"] or r["result"] is None:
        vd["ERROR"] = vd.get("ERROR", 0) + 1
    elif r["result"].startswith("MALICIOUS"):
        vd["MALICIOUS"] = vd.get("MALICIOUS", 0) + 1
    elif r["result"] == "WHITELIST":
        vd["WHITELIST"] = vd.get("WHITELIST", 0) + 1
    else:
        vd["CLEAN"] = vd.get("CLEAN", 0) + 1
stats["verdict_dist"] = vd

with open(os.path.join(BASE, "_spot_stats_v2.json"), "w", encoding="utf-8") as f:
    json.dump(stats, f, ensure_ascii=False, indent=1)
print("stats written")
