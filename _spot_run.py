# -*- coding: utf-8 -*-
"""SevenEngine v0.0.2 spot test harness.
Stratified sampling from malware corpus + white corpora, in-process scan,
record per-file result/confidence/engine-tag/latency -> JSONL + summary JSON.
"""
import os, sys, json, time, random, traceback
BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
sys.path.insert(0, BASE)

SEED = 20260924
random.seed(SEED)

VIRUS_ROOT = r"D:\训练病毒"
WHITE_ROOTS = [r"C:\Program Files", r"C:\Program Files (x86)"]
SYS_ROOTS = [r"C:\Windows\System32"]

PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".com"}
SCRIPT_EXTS = {".js", ".bat", ".cmd", ".vbs", ".ps1", ".vbe", ".wsf", ".hta", ".sct", ".py", ".pyw"}

# ---- v2: enlarged sample to tighten FPR confidence interval ----
RUN_TAG = "v2"
N_VIRUS_PE = 400        # stratified by top-level folder, cap 50/folder
N_VIRUS_SCRIPT = 40
N_VIRUS_OTHER = 60      # scan-rate-only group
N_WHITE_PF = 600
N_WHITE_PF86 = 150
N_SYS_PE = 250
CAP_PER_FOLDER = 50

def is_mz(p):
    try:
        with open(p, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False

def collect_virus(root):
    """Walk virus corpus, bucket MZ PEs by top-level folder; scripts; others."""
    pe_by_folder = {}
    scripts, others = [], []
    for dp, dn, fs in os.walk(root):
        top = os.path.relpath(dp, root).split(os.sep)[0]
        for f in fs:
            p = os.path.join(dp, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in SCRIPT_EXTS:
                scripts.append(p)
                continue
            if ext in PE_EXTS or is_mz(p):
                pe_by_folder.setdefault(top, []).append(p)
            else:
                others.append(p)
    return pe_by_folder, scripts, others

def collect_mz(roots, cap_per_root=None):
    out = []
    for r in roots:
        cnt = 0
        for dp, dn, fs in os.walk(r):
            for f in fs:
                p = os.path.join(dp, f)
                if is_mz(p):
                    out.append((r, p))
                    cnt += 1
                    if cap_per_root and cnt >= cap_per_root:
                        break
            if cap_per_root and cnt >= cap_per_root:
                break
    return out

def main():
    meta = {"seed": SEED, "t_start": time.strftime("%Y-%m-%d %H:%M:%S")}
    print("[1/4] collecting virus corpus index ...", flush=True)
    t0 = time.time()
    pe_by_folder, scripts, others = collect_virus(VIRUS_ROOT)
    meta["virus_index_sec"] = round(time.time() - t0, 1)
    meta["virus_folders"] = len(pe_by_folder)
    meta["virus_pe_total"] = sum(len(v) for v in pe_by_folder.values())
    meta["virus_scripts_total"] = len(scripts)
    meta["virus_others_total"] = len(others)
    print(f"      folders={meta['virus_folders']} pe={meta['virus_pe_total']} "
          f"scripts={meta['virus_scripts_total']} others={meta['virus_others_total']}", flush=True)

    # stratified sampling: proportional per folder, cap 50, min 3
    total_pe = meta["virus_pe_total"]
    sample = []
    for folder, paths in sorted(pe_by_folder.items()):
        share = max(3, min(CAP_PER_FOLDER, round(len(paths) / total_pe * N_VIRUS_PE)))
        random.shuffle(paths)
        for p in paths[:share]:
            sample.append((p, folder))
    random.shuffle(scripts)
    for p in scripts[:N_VIRUS_SCRIPT]:
        sample.append((p, "_scripts_"))
    random.shuffle(others)
    others_sample = others[:N_VIRUS_OTHER]
    meta["virus_pe_sampled"] = sum(1 for p, f in sample)
    print(f"      sampled virus PE={meta['virus_pe_sampled']} scripts={min(N_VIRUS_SCRIPT, len(scripts))} others={len(others_sample)}", flush=True)

    print("[2/4] collecting white corpus PEs ...", flush=True)
    pf = collect_mz([r"C:\Program Files"], cap_per_root=None)
    pf86 = collect_mz([r"C:\Program Files (x86)"], cap_per_root=None)
    syspe = collect_mz(SYS_ROOTS, cap_per_root=None)
    random.shuffle(pf)
    random.shuffle(pf86)
    random.shuffle(syspe)
    white = pf[:N_WHITE_PF] + pf86[:N_WHITE_PF86]
    syspe = syspe[:N_SYS_PE]
    meta["white_sampled"] = len(white)
    meta["sys_sampled"] = len(syspe)
    print(f"      white={len(white)} (pf={min(N_WHITE_PF,len(pf))} pf86={min(N_WHITE_PF86,len(pf86))}) sys={len(syspe)}", flush=True)

    print("[3/4] loading engine ...", flush=True)
    import SevenEngine as SE
    s = SE.Scanner()
    meta["lgbm"] = bool(s.lgbm and getattr(s.lgbm, "available", False))
    meta["onnx"] = bool(s.onnx and getattr(s.onnx, "session", None) is not None)
    print(f"      lgbm={meta['lgbm']} onnx={meta['onnx']}", flush=True)

    rows = []
    def run_group(path, label, family):
        t0 = time.time()
        rec = {"path": path, "group": label, "family": family,
               "result": None, "conf": 0, "type": "", "sec": 0, "err": None}
        try:
            res, conf, t = s.scan_file(path)
            rec["result"] = res
            rec["conf"] = conf
            rec["type"] = t
        except Exception as e:
            rec["err"] = f"{type(e).__name__}: {e}"[:200]
        rec["sec"] = round(time.time() - t0, 3)
        rows.append(rec)

    print("[4/4] scanning ...", flush=True)
    t_scan = time.time()
    for i, (p, folder) in enumerate(sample):
        run_group(p, "virus_pe" if not p.endswith(tuple(SCRIPT_EXTS)) else "virus_script", folder)
        if (i + 1) % 50 == 0:
            print(f"      virus {i+1}/{len(sample)}  elapsed={time.time()-t_scan:.0f}s", flush=True)
    for p in others_sample:
        run_group(p, "virus_other", "_others_")
    print(f"      virus done  elapsed={time.time()-t_scan:.0f}s", flush=True)
    for i, (root, p) in enumerate(white):
        gname = "white_pf_x86" if "(x86)" in root else "white_pf"
        run_group(p, gname, root)
    for i, (root, p) in enumerate(syspe):
        run_group(p, "white_sys", root)
    meta["scan_sec"] = round(time.time() - t_scan, 1)
    meta["t_end"] = time.strftime("%Y-%m-%d %H:%M:%S")

    with open(os.path.join(BASE, f"_spot_raw_{RUN_TAG}.jsonl"), "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    json.dump(meta, open(os.path.join(BASE, f"_spot_meta_{RUN_TAG}.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(f"DONE rows={len(rows)} scan_sec={meta['scan_sec']}", flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        with open(os.path.join(BASE, "_spot_crash.txt"), "w", encoding="utf-8") as f:
            f.write(traceback.format_exc())
        raise
