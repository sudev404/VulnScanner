def calculate_risk(findings: list) -> dict:
    """
    Calculates a 0–100 risk score from all findings.
    Weights: Critical=40, High=20, Medium=8, Low=3, Info=0
    """
    weights = {"Critical": 40, "High": 20, "Medium": 8, "Low": 3, "Info": 0}
    MAX_SCORE = 100

    raw = 0
    for f in findings:
        sev = getattr(f, "severity", None) or f.get("severity", "Info")
        raw += weights.get(sev, 0)

    # Normalize to 0–100 (cap at 200 raw = 100 normalized)
    score = min(round((raw / 200) * 100, 1), 100.0)

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Info"

    return {"score": score, "level": level, "raw": raw}
