"""Owner-authorised camera exposure assessment and responsible-disclosure helper.

Offline, self-reported checklist only. No host connections, scans or video access.
"""
from __future__ import annotations
from datetime import datetime, timezone

QUESTIONS = {
    "internet_exposed": ("Is management reachable from the public internet? (yes/no/unknown): ", 5, "Management interface may be internet-reachable", "Remove direct internet exposure; use a VPN or zero-trust gateway and restrict sources."),
    "remote_admin": ("Is remote administration enabled? (yes/no/unknown): ", 4, "Remote administration is enabled", "Disable remote administration unless required; restrict it to named administrators."),
    "https": ("Does management enforce valid HTTPS? (yes/no/unknown): ", 3, "HTTPS protection is absent or unverified", "Enable HTTPS with a valid maintained certificate; disable insecure management where supported."),
    "unique_credentials": ("Are all accounts using unique, non-default passwords? (yes/no/unknown): ", 5, "Unique non-default credentials are absent or unverified", "Replace defaults/shared passwords; remove unused accounts and use a password manager."),
    "mfa": ("Is MFA enabled for remote/cloud/admin access where supported? (yes/no/unknown): ", 2, "MFA is absent or unverified", "Enable MFA for cloud portals, remote access and administrator accounts."),
    "firmware_current": ("Is firmware vendor-supported and patched? (yes/no/unknown): ", 4, "Firmware support or patch status is not confirmed", "Check the exact model against vendor advisories and apply signed vendor updates."),
    "vendor_support": ("Does the manufacturer still provide security updates? (yes/no/unknown): ", 4, "Manufacturer security support may have ended", "Confirm end-of-support status; replace unsupported devices or isolate them."),
    "upnp_forwarding": ("Is UPnP or router port-forwarding configured? (yes/no/unknown): ", 3, "UPnP or direct port forwarding may expose services", "Disable UPnP and remove unnecessary forwarding; use controlled remote access."),
    "segmentation": ("Is the camera network isolated from user/workstation networks? (yes/no/unknown): ", 2, "Network segmentation is absent or unverified", "Use a dedicated VLAN and restrict traffic to required systems."),
    "logging": ("Are administrator logins and security events monitored? (yes/no/unknown): ", 1, "Security-event monitoring is absent or unverified", "Enable audit logs and alert on unexpected administrator logins and configuration changes."),
}

def _answer(value):
    answer = str(value).strip().lower()
    if answer not in {"yes", "no", "unknown"}:
        raise ValueError("Answers must be yes, no, or unknown.")
    return answer

def assess_camera_configuration(asset, answers):
    """Score operator-supplied answers; findings are not independently verified."""
    if set(answers) != set(QUESTIONS):
        raise ValueError("Provide exactly one answer for each camera security control.")
    cleaned = {key: _answer(value) for key, value in answers.items()}
    score, findings, verification = 0, [], []
    for key, (prompt, weight, finding, recommendation) in QUESTIONS.items():
        answer = cleaned[key]
        insecure_yes = key in {"internet_exposed", "remote_admin", "upnp_forwarding"}
        if (answer == "yes" and insecure_yes) or (answer == "no" and not insecure_yes):
            score += weight
            findings.append({"control": key, "observation": finding, "recommendation": recommendation})
        elif answer == "unknown":
            score += 1
            verification.append({"control": key, "status": "not_verified", "next_step": "Confirm using device configuration or vendor documentation."})
    level = "critical" if score >= 20 else "high" if score >= 13 else "medium" if score >= 6 else "low"
    return {
        "feature": "camera_exposure_defence_assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "asset": {k: str(v).strip()[:160] for k, v in asset.items() if str(v).strip()},
        "risk_score": score, "risk_level": level,
        "assessment_basis": "Self-reported operator answers; not technical verification or proof of internet exposure.",
        "answers": cleaned, "findings": findings, "verification_required": verification,
        "scope": "Offline checklist only. No host contacted, no port scanned, no camera feed or credentials accessed.",
        "score_note": "CyberLab triage aid, not a CVSS score or proof that the device is exploitable.",
    }

def build_responsible_disclosure_template(asset, findings):
    label = str(asset.get("label") or asset.get("model") or "camera/NVR asset").strip()[:160]
    observations = "\n".join(
        "- {}: {}".format(item.get("observation", "Configuration concern"), item.get("recommendation", "Please review."))
        for item in findings
    ) or "- Potential exposure requires confirmation by the asset owner."
    return (
        "Subject: Responsible security report — camera system configuration concern\n\n"
        "Hello Security Team,\n\n"
        "I am contacting you about a potential security concern involving {}. "
        "I am reporting this so your team can verify and remediate it.\n\n"
        "Observed / owner-provided assessment points:\n{}\n\n"
        "Assessment limitations: these notes are based on the information stated in the report. "
        "I did not bypass authentication, access private video, retrieve credentials, or test an unapproved system.\n\n"
        "Please let me know the appropriate secure channel for coordinating verification and remediation. "
        "I will keep the details confidential while your team investigates.\n\nRegards,\n[Your name / contact]"
    ).format(label, observations)

def run_camera_exposure_assessment():
    print("\nCAMERA EXPOSURE ASSESSMENT & DEFENCE")
    print("Use only for a camera/NVR system you own, administer, or are explicitly authorised to assess.")
    if input("Type YES to confirm authorisation for this assessment: ").strip() != "YES":
        raise ValueError("Assessment cancelled; explicit authorisation confirmation is required.")
    asset = {
        "label": input("Asset label/site (optional): ").strip(),
        "manufacturer": input("Manufacturer (optional): ").strip(),
        "model": input("Camera/NVR model (optional): ").strip(),
        "firmware": input("Firmware version (optional): ").strip(),
        "owner_or_organisation": input("Owner/organisation (optional): ").strip(),
    }
    answers = {key: _answer(input(spec[0])) for key, spec in QUESTIONS.items()}
    report = assess_camera_configuration(asset, answers)
    report["responsible_disclosure_template"] = build_responsible_disclosure_template(asset, report["findings"])
    print("\nAssessment complete — {} triage level (score {}).".format(report["risk_level"].upper(), report["risk_score"]))
    print("Self-reported only; this does not independently verify exposure.")
    print("Findings: {}; controls requiring verification: {}.".format(len(report["findings"]), len(report["verification_required"])))
    return report
