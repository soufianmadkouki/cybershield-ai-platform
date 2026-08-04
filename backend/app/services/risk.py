from app.models import Asset, Vulnerability


def calculate_vulnerability_risk_score(
    vulnerability: Vulnerability,
    asset: Asset,
    *,
    is_exploitable: bool = False,
) -> float:
    score = 0.0

    cvss_score = (
        vulnerability.cvss_v4_score
        or vulnerability.cvss_v3_score
        or vulnerability.cvss_v2_score
        or 0.0
    )

    score += cvss_score * 5.0

    if vulnerability.epss_score is not None:
        score += vulnerability.epss_score * 20.0

    if vulnerability.is_cisa_kev:
        score += 15.0

    if vulnerability.is_patch_available:
        score += 2.0

    if is_exploitable:
        score += 10.0

    criticality_weights = {
        "critical": 10.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }

    score += criticality_weights.get(
        asset.criticality.value,
        0.0,
    )

    return round(min(score, 100.0), 2)
