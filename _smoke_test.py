# -*- coding: utf-8 -*-
"""Smoke test: deps, engine load, single scan, cloud connectivity."""
import os, sys, json, time
BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
out = {}

# 1) deps
deps = {}
for m in ("pefile", "cryptography", "onnxruntime", "lightgbm", "requests"):
    try:
        __import__(m)
        deps[m] = "OK"
    except Exception as e:
        deps[m] = f"FAIL: {e}"
out["deps"] = deps

# 2) cloud connectivity (5s probe)
try:
    import requests
    t0 = time.time()
    r = requests.post(CONFIG_URL := "https://cloudapi.xiguastudio.top", timeout=5)
    out["cloud_ping"] = {"status": r.status_code, "sec": round(time.time() - t0, 2)}
except Exception as e:
    out["cloud_ping"] = f"FAIL: {type(e).__name__}: {e}"[:200]

# 3) engine load
sys.path.insert(0, BASE)
t0 = time.time()
import SevenEngine as SE
out["import_sec"] = round(time.time() - t0, 2)
t0 = time.time()
s = SE.Scanner()
out["scanner_init_sec"] = round(time.time() - t0, 2)
out["lgbm_available"] = bool(s.lgbm and getattr(s.lgbm, "available", False))
out["onnx_available"] = bool(s.onnx and getattr(s.onnx, "session", None) is not None)
out["study_hashes"] = len(getattr(s.study, "records", {})) if hasattr(s.study, "records") else "n/a"

# 4) scan known files
tests = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\explorer.exe"]
out["scans"] = []
for p in tests:
    if not os.path.exists(p):
        continue
    t0 = time.time()
    try:
        res, conf, t = s.scan_file(p)
        out["scans"].append({"path": p, "result": res, "conf": conf, "type": t, "sec": round(time.time() - t0, 2)})
    except Exception as e:
        out["scans"].append({"path": p, "error": f"{type(e).__name__}: {e}"[:200]})

json.dump(out, open(os.path.join(BASE, "_smoke.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
