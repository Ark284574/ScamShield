"""Run the ScamShield test set against the real model and score the results.

Usage (from the project folder, with Ollama running):
    .\\.venv\\Scripts\\python.exe run_tests.py
    .\\.venv\\Scripts\\python.exe run_tests.py --ids S02 L01
    .\\.venv\\Scripts\\python.exe run_tests.py --limit 5
"""
import argparse
import csv
import json
import time
from pathlib import Path

from analyzer import ScamShieldError, analyze_message, check_ollama

OVERCLAIMS = ["definitely a scam", "definitely fraud", "certainly a scam", "100% safe",
              "completely safe", "guaranteed safe", "definitely safe", "is definitely"]
HIGH = {"High", "Critical"}
LOW = {"Low", "Unclear", "Moderate"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="tests/test_messages.json")
    ap.add_argument("--ids", nargs="*", help="only run these ids, e.g. S02 L01")
    ap.add_argument("--limit", type=int, help="only run the first N messages")
    args = ap.parse_args()

    ok, health = check_ollama()
    print(("OK  " if ok else "WARN ") + health + "\n")

    cases = json.loads(Path(args.file).read_text(encoding="utf-8"))
    if args.ids:
        cases = [c for c in cases if c["id"] in args.ids]
    if args.limit:
        cases = cases[: args.limit]

    results = []
    for c in cases:
        start = time.time()
        try:
            r = analyze_message(c["text"])
            level, score, err = r["risk_level"], r["risk_score"], ""
            text_blob = (r["summary"] + " " + " ".join(w["explanation"] for w in r["warning_signs"])).lower()
            overclaim = any(p in text_blob for p in OVERCLAIMS)
        except ScamShieldError as exc:
            r, level, score, err, overclaim = None, "ERROR", 0, str(exc), False
        secs = round(time.time() - start, 1)
        passed = level in c["acceptable_levels"] and not overclaim
        missed_scam = c["category"] == "scam" and level in LOW
        false_alarm = c["category"] == "legit" and level in HIGH
        results.append(dict(id=c["id"], category=c["category"], level=level, score=score,
                            acceptable="/".join(c["acceptable_levels"]), passed=passed,
                            missed_scam=missed_scam, false_alarm=false_alarm,
                            overclaim=overclaim, seconds=secs, error=err, report=r))
        flag = "PASS" if passed else "FAIL"
        extra = " (overclaim wording)" if overclaim else ""
        print(f"{flag}  {c['id']}  {c['category']:7}  got {level:9} want {'/'.join(c['acceptable_levels']):26} {secs:5}s{extra} {err}")

    n = len(results)
    print("\n=== SUMMARY ===")
    print(f"Passed: {sum(x['passed'] for x in results)}/{n}")
    for cat in ("scam", "legit", "unclear"):
        sub = [x for x in results if x["category"] == cat]
        if sub:
            print(f"  {cat:8} {sum(x['passed'] for x in sub)}/{len(sub)}")
    print(f"Missed scams (scam rated low/unclear/moderate): {sum(x['missed_scam'] for x in results)}")
    print(f"False alarms (legit rated high/critical):        {sum(x['false_alarm'] for x in results)}")
    print(f"Errors: {sum(x['level'] == 'ERROR' for x in results)}")
    if n:
        print(f"Average time: {round(sum(x['seconds'] for x in results) / n, 1)}s per message")

    out = Path("tests/results")
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (out / f"results-{stamp}.json").write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    with open(out / f"results-{stamp}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        cols = ["id", "category", "level", "score", "acceptable", "passed", "missed_scam", "false_alarm", "overclaim", "seconds", "error"]
        w.writerow(cols)
        for x in results:
            w.writerow([x[k] for k in cols])
    print(f"\nSaved to tests/results/results-{stamp}.csv and .json")


if __name__ == "__main__":
    main()
