# -*- coding: utf-8 -*-
import subprocess, json, os
CANDS = [
    r"C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe",
    r"C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe",
    r"C:\Users\Administrator\.workbuddy\binaries\python\envs\default\Scripts\python.exe",
]
CODE = (
    "import importlib.util as u, json; "
    "pkgs=['pefile','cryptography','onnxruntime','lightgbm','requests','numpy','pandas']; "
    "print(json.dumps({p: bool(u.find_spec(p)) for p in pkgs}))"
)
out = {}
for exe in CANDS:
    if not os.path.exists(exe):
        out[exe] = "NOT FOUND"
        continue
    try:
        r = subprocess.run([exe, "-c", CODE], capture_output=True, text=True, timeout=60)
        out[exe] = (r.stdout or r.stderr).strip()[:400]
    except Exception as e:
        out[exe] = f"ERR {e}"
json.dump(out, open(r"D:\Administrator\Desktop\Releasesv0.0.2\_envs.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
