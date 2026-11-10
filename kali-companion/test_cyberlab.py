"""Unit tests for the CyberLab AI Kali companion."""
import hashlib
import json
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("cyberlab.py")
SPEC = importlib.util.spec_from_file_location("cyberlab", MODULE_PATH)
cyberlab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(cyberlab)


class CompanionTests(unittest.TestCase):

    def test_investigation_report_is_saved_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                report = cyberlab.save_investigation({"status": "ok"}, "DNS intelligence")
                self.assertTrue(report.exists())
                self.assertIn("dns-intelligence", report.name)
                self.assertIn('"status": "ok"', report.read_text(encoding="utf-8"))


    def test_url_analysis_flags_http_without_visiting_url(self):
        result = cyberlab.analyze_url("http://example.test/login")
        self.assertEqual(result["normalized_host"], "example.test")
        self.assertIn("URL does not use HTTPS", result["structural_indicators"])
        self.assertIn("NOT opened", result["risk_note"])

    def test_url_analysis_rejects_non_http_scheme(self):
        with self.assertRaisesRegex(ValueError, "HTTP or HTTPS"):
            cyberlab.analyze_url("file:///etc/passwd")

    def test_dns_intelligence_email_findings_classify_spf_and_dmarc(self):
        records = {
            "MX": {"answers": [{"value": "10 mail.example.test"}]},
            "TXT": {"answers": [{"value": "v=spf1 include:mail.example.test ~all"}]},
            "DMARC": {"answers": [{"value": "v=DMARC1; p=none; rua=mailto:dmarc@example.test"}]},
            "CAA": {"answers": [{"value": '0 issue "ca.example"'}]},
        }
        result = cyberlab._email_security_findings("example.test", records, "person@example.test")
        self.assertEqual(result["spf_terminal_qualifiers"], ["soft_fail"])
        self.assertEqual(result["dmarc_policy"], ["none"])
        self.assertEqual(result["mailbox_existence"], "Not tested")
        self.assertTrue(any("DMARC policy is p=none" == item["finding"] for item in result["findings"]))

    def test_dns_intelligence_email_flags_multiple_spf_records(self):
        records = {
            "MX": {"answers": []},
            "TXT": {"answers": [{"value": "v=spf1 -all"}, {"value": "v=spf1 ~all"}]},
            "DMARC": {"answers": []},
            "CAA": {"answers": []},
        }
        result = cyberlab._email_security_findings("example.test", records)
        self.assertEqual(result["spf_policy_count"], 2)
        self.assertTrue(any(item["severity"] == "high" and "Multiple SPF" in item["finding"] for item in result["findings"]))

    def test_dns_intelligence_url_findings_keep_query_values_private(self):
        result = cyberlab._url_intelligence_findings("https://example.test/login?token=secret&next=%2Fhome#section")
        self.assertIn("token", result["query_parameter_names"])
        self.assertNotIn("secret", repr(result))
        self.assertTrue(result["query_values_saved"] is False)
        self.assertTrue(any("authentication route" in item for item in result["enhanced_indicators"]))
        self.assertIn("Not performed", result["reputation_check"])

    def test_public_page_parser_detects_login_form_without_submitting(self):
        parser = cyberlab._PageMetadata()
        parser.feed("<title>Example Portal</title><meta name=\"description\" content=\"Example service\"><form><input name=\"email\" type=\"email\"><input name=\"password\" type=\"password\"></form>")
        self.assertEqual(" ".join(parser.title), "Example Portal")
        self.assertEqual(parser.meta["description"], "Example service")
        self.assertEqual(parser.forms[0]["fields"][1]["type"], "password")

    def test_rdap_summary_extracts_registry_dates(self):
        data = {"events": [{"eventAction": "registration", "eventDate": "2020-01-01"}], "name": "Example Net", "country": "NG"}
        summary = cyberlab._rdap_summary(data)
        self.assertEqual(summary["registered_on"], "2020-01-01")
        self.assertEqual(summary["registrar_or_network_name"], "Example Net")
    def test_manual_assessment_records_passive_page_and_admin_checks(self):
        # The assessment currently asks 15 checklist questions. Keep the
        # mocked input sequence aligned with that count so optional URL and
        # evidence prompts receive their intended values.
        answers = (
            ["staging.example.test", "yes"]
            + ["yes"] * 15
            + [
                "https://staging.example.test/login",
                "https://staging.example.test/admin",
                "Reviewed source and cookie configuration.",
            ]
        )
        page_result = {"status_code": 200, "login_classification": "email/password form pattern", "cookies": []}
        admin_result = {"status_code": 401, "redirects_followed": False}
        with patch("builtins.input", side_effect=answers), patch.object(
            cyberlab, "inspect_assessment_page", side_effect=[page_result, admin_result]
        ) as inspect:
            result = cyberlab.manual_security_assessment()
        self.assertTrue(result["authorisation_confirmed_by_operator"])
        self.assertEqual(result["login_method"], "email/password form pattern")
        self.assertEqual(result["page_inspection"]["status_code"], 200)
        self.assertEqual(result["admin_response_inspection"]["status_code"], 401)
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(inspect.call_args_list[0].kwargs["method"], "GET")
        self.assertEqual(inspect.call_args_list[1].kwargs["method"], "HEAD")
        self.assertIn("Potential authentication bypass", result["sql_injection_explanation"]["impact"])

    def test_assessment_url_rejects_private_network_address(self):
        with self.assertRaisesRegex(ValueError, "non-public"):
            cyberlab._validate_assessment_url("https://127.0.0.1/admin")

    def test_static_triage_hash_and_signature(self):
        payload = b"MZ" + b"sample executable content"
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(payload)
            result = cyberlab.triage_file(sample)
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertIn("Windows PE", result["file_type"])
        self.assertGreaterEqual(result["entropy"], 0)
        self.assertLessEqual(result["entropy"], 8)

    def test_empty_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "empty.bin"
            sample.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                cyberlab.triage_file(sample)

    def test_domain_validation(self):
        self.assertEqual(cyberlab.validate_domain("Example.COM."), "example.com")
        with self.assertRaisesRegex(ValueError, "valid public domain"):
            cyberlab.validate_domain("not a domain")

    def test_private_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "public global"):
            cyberlab.ip_intelligence("127.0.0.1")

    def test_invalid_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "valid IPv4 or IPv6"):
            cyberlab.ip_intelligence("999.999.999.999")

    def test_nmap_xml_summary(self):
        xml = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="lab.example.test" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Example" version="1.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "scan.xml"
            report.write_bytes(xml)
            result = cyberlab.parse_nmap_xml(report)
        self.assertEqual(result["summary"]["hosts"], 1)
        self.assertEqual(result["summary"]["hosts_up"], 1)
        self.assertEqual(result["summary"]["open_ports"], 1)
        self.assertEqual(result["open_ports"][0]["port"], 443)
        self.assertEqual(result["open_ports"][0]["service"], "https")

    def test_nmap_xml_rejects_entity_declarations(self):
        xml = b'<!DOCTYPE nmaprun [<!ENTITY x "expanded">]><nmaprun>&x;</nmaprun>'
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "unsafe.xml"
            report.write_bytes(xml)
            with self.assertRaisesRegex(ValueError, "entity"):
                cyberlab.parse_nmap_xml(report)

    def test_nmap_xml_rejects_wrong_root(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "wrong.xml"
            report.write_text("<root/>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "root"):
                cyberlab.parse_nmap_xml(report)


    def test_hash_inventory_classifies_formats_without_returning_values(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "hashes.txt"
            inventory.write_text("$2b$12$example\n" + "a" * 32 + "\n" + "b" * 64 + "\n", encoding="utf-8")
            result = cyberlab.classify_hash_inventory(inventory)
        self.assertEqual(result["nonempty_records_reviewed"], 3)
        self.assertEqual(result["format_counts"]["bcrypt"], 1)
        self.assertEqual(result["format_counts"]["32-character hex (MD5-like; ambiguous)"], 1)
        self.assertFalse(result["hash_values_saved"])
        self.assertFalse(result["cracking_attempted"])

    def test_hash_inventory_rejects_missing_file(self):
        with self.assertRaisesRegex(ValueError, "existing local"):
            cyberlab.classify_hash_inventory(Path("/definitely/not/a/real/hash-inventory.txt"))


    def test_evidence_registration_and_integrity_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("authorised evidence", encoding="utf-8")
            with patch.object(cyberlab.Path, "home", return_value=root):
                registered = cyberlab.register_evidence(source, "case-17", "test evidence")
                verified = cyberlab.verify_evidence_integrity()
                self.assertEqual(verified["integrity_valid"], 1)
                evidence_path = Path(registered["evidence_path"])
                evidence_path.write_text("changed", encoding="utf-8")
                changed = cyberlab.verify_evidence_integrity()
                self.assertEqual(len(changed["hash_mismatches_or_invalid_manifests"]), 1)

    def test_evidence_registration_rejects_symbolic_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("evidence", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(source)
            with patch.object(cyberlab.Path, "home", return_value=root):
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    cyberlab.register_evidence(link)

    def test_triage_reports_extension_signature_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "disguised.exe"
            sample.write_bytes(b"%PDF-1.7\nnot an executable")
            result = cyberlab.triage_file(sample)
        self.assertTrue(result["extension_signature_mismatch"])
        self.assertIn("PDF", result["file_type"])

    def test_nmap_xml_includes_service_inventory_summary(self):
        xml = b"<nmaprun><host><status state='up'/><address addr='192.0.2.2' addrtype='ipv4'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https' product='Example' version='2.0'/></port></ports></host></nmaprun>"
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "scan.xml"
            report.write_bytes(xml)
            result = cyberlab.parse_nmap_xml(report)
        self.assertEqual(result["summary"]["open_service_counts"]["https"], 1)
        self.assertEqual(result["versioned_services"][0]["version"], "2.0")

    def test_cve_search_enriches_weakness_and_cpe_metadata(self):
        payload = {"totalResults": 1, "vulnerabilities": [{"cve": {
            "id": "CVE-2025-0001", "descriptions": [{"lang": "en", "value": "Example issue"}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "references": [{"url": "https://example.test/advisory", "tags": ["Vendor Advisory"]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "1.2"}]}]}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/example"}}]}
        }}]}
        with patch.object(cyberlab, "http_json", return_value=payload):
            result = cyberlab.cve_search("Example")
        item = result["results"][0]
        self.assertEqual(item["weaknesses"], ["CWE-79"])
        self.assertEqual(item["affected_product_configurations"][0]["version_end_excluding"], "1.2")
        self.assertEqual(item["cvss_vector"], "CVSS:3.1/example")


    def test_password_audit_flags_predictable_sequences_without_returning_secret(self):
        secret = "Qwerty123456!!!"
        result = cyberlab.audit_password_strength(secret)
        self.assertTrue(result["risk_signals"]["keyboard_or_sequential_pattern"])
        self.assertNotIn(secret, repr(result))
        self.assertIn("assessment_limit", result)

    def test_password_audit_recognises_long_unique_candidate(self):
        result = cyberlab.audit_password_strength("violet-harbour-copper-orbit-74")
        self.assertEqual(result["quality_band"], "strong_candidate")

    def test_password_storage_review_flags_fast_hashes(self):
        result = cyberlab.review_password_storage("sha256", "no", "")
        self.assertEqual(result["status"], "weak_or_inappropriate")
        self.assertFalse(result["salted"])


    def test_investigation_report_integrity_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                report = cyberlab.save_investigation({"finding": "initial"}, "case report")
                valid = cyberlab.verify_investigation_reports()
                self.assertEqual(valid["integrity_valid"], 1)
                report.write_text('{"finding":"changed"}', encoding="utf-8")
                altered = cyberlab.verify_investigation_reports()
                self.assertEqual(len(altered["hash_mismatches_or_invalid_manifests"]), 1)

    def test_investigation_reports_do_not_overwrite_same_second(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                first = cyberlab.save_investigation({"n": 1}, "repeat")
                second = cyberlab.save_investigation({"n": 2}, "repeat")
                self.assertNotEqual(first.name, second.name)
                self.assertTrue(first.exists())
                self.assertTrue(second.exists())


    def test_case_timeline_appends_and_verifies_hash_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                first = cyberlab.append_case_event("CASE-42", "observation", "Public page showed a contact form.")
                second = cyberlab.append_case_event("CASE-42", "collection", "Saved public page metadata.", "evidence-01")
                result = cyberlab.verify_case_timeline("CASE-42")
                timeline = cyberlab.read_case_timeline("CASE-42")
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["events_checked"], 2)
        self.assertEqual(len(timeline["events"]), 2)
        self.assertEqual(second["event"]["previous_entry_hash"], first["event"]["entry_hash"])

    def test_case_timeline_detects_modified_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                cyberlab.append_case_event("CASE-43", "note", "Initial observation recorded.")
                path = cyberlab.case_timeline_path("CASE-43")
                event = json.loads(path.read_text(encoding="utf-8"))
                event["description"] = "Altered observation."
                path.write_text(json.dumps(event) + "\n", encoding="utf-8")
                result = cyberlab.verify_case_timeline("CASE-43")
        self.assertEqual(result["status"], "entry_hash_mismatch")

    def test_case_timeline_rejects_empty_case_id(self):
        with self.assertRaisesRegex(ValueError, "Case/reference ID"):
            cyberlab.case_timeline_path(" !!! ")


    def test_case_timeline_strips_url_query_and_fragment(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                result = cyberlab.append_case_event(
                    "CASE-44", "reference", "Recorded public reference.",
                    "https://example.org/report?id=private-token#section"
                )
        self.assertEqual(
            result["event"]["source_reference"],
            "https://example.org/report"
        )

    def test_case_timeline_refuses_append_after_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cyberlab.Path, "home", return_value=Path(directory)):
                cyberlab.append_case_event("CASE-45", "note", "Original event.")
                path = cyberlab.case_timeline_path("CASE-45")
                event = json.loads(path.read_text(encoding="utf-8"))
                event["description"] = "Tampered event."
                path.write_text(json.dumps(event) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "failed integrity verification"):
                    cyberlab.append_case_event("CASE-45", "note", "Do not extend a broken chain.")

    def test_case_timeline_rejects_url_with_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "without embedded credentials"):
            cyberlab._safe_timeline_source_reference("https://user:pass@example.org/path")


    def test_dns_intelligence_accepts_email_address(self):
        result = cyberlab._normalise_osint_input("security@example.org")
        self.assertEqual(result["input_type"], "email")
        self.assertEqual(result["domain"], "example.org")
        self.assertEqual(result["email_address"], "security@example.org")

    def test_dns_intelligence_accepts_social_profile_as_reference(self):
        result = cyberlab._normalise_osint_input("https://www.linkedin.com/company/example/")
        self.assertEqual(result["input_type"], "social_profile_url")
        self.assertEqual(result["platform_host"], "www.linkedin.com")
        self.assertIsNone(result["domain"])

    def test_dns_intelligence_resolves_only_public_addresses(self):
        with patch.object(cyberlab.socket, "getaddrinfo", return_value=[
            (None, None, None, None, ("93.184.216.34", 0)),
            (None, None, None, None, ("10.0.0.1", 0)),
        ]):
            result = cyberlab.resolve_public_site_ips("example.org")
        self.assertEqual(result["addresses"], ["93.184.216.34"])
        self.assertEqual(result["count"], 1)

    def test_dns_intelligence_social_reference_does_not_claim_member_count(self):
        result = cyberlab.dns_intelligence_lookup("https://facebook.com/example")
        self.assertEqual(result["sources"]["social_profile"]["status"], "reference_only")
        self.assertIn("Not reliably available", result["sources"]["social_profile"]["follower_or_member_count"])


    def test_password_storage_review_rejects_unrecognised_answers(self):
        with self.assertRaisesRegex(ValueError, "enter yes, no, unknown"):
            cyberlab.review_password_storage("bcrypt", "yes", "1")

    def test_password_storage_review_preserves_unknown_status(self):
        result = cyberlab.review_password_storage("bcrypt", "unknown", "no")
        self.assertEqual(result["salt_status"], "unknown")
        self.assertFalse(result["salted"])
        self.assertEqual(result["work_factor_status"], "no")
        self.assertFalse(result["work_factor_or_parameters_documented"])



    def test_john_audit_runs_offline_and_discards_plaintext_output(self):
        with tempfile.TemporaryDirectory() as directory:
            hashes = Path(directory) / "hashes.txt"
            wordlist = Path(directory) / "rockyou.txt"
            hashes.write_text("test-hash-record", encoding="utf-8")
            wordlist.write_text("candidate-password", encoding="utf-8")
            completed = [
                __import__("subprocess").CompletedProcess([], 0, "Loaded 1 password hash", ""),
                __import__("subprocess").CompletedProcess([], 0, "labuser:RecoveredSecret:1000:1000:::" + chr(10) + "1 password hash cracked, 0 left" + chr(10), ""),
            ]
            with patch.object(cyberlab.shutil, "which", return_value="/usr/bin/john"):
                with patch.object(cyberlab.subprocess, "run", side_effect=completed) as run:
                    result = cyberlab.run_john_audit(hashes, wordlist, authorised=True)
            self.assertEqual(result["cracked_hash_count"], 1)
            self.assertEqual(result["remaining_hash_count"], 0)
            self.assertFalse(result["plaintext_passwords_returned_or_saved"])
            self.assertNotIn("RecoveredSecret", json.dumps(result))
            self.assertIn("--wordlist=" + str(wordlist), run.call_args_list[0].args[0])
            self.assertNotIn("shell", run.call_args_list[0].kwargs)

    def test_john_audit_requires_authorisation(self):
        with self.assertRaisesRegex(ValueError, "Confirm that you own"):
            cyberlab.run_john_audit(Path("hashes.txt"), Path("rockyou.txt"))

    def test_scam_menu_option_three_uses_website_url_not_local_log(self):
        with patch("builtins.input", side_effect=["3", "https://example.test/login"]):
            with patch.object(cyberlab, "inspect_assessment_page", return_value={"status_code": 200}) as inspect:
                result = cyberlab.scam_investigation_menu()
        inspect.assert_called_once_with("https://example.test/login", timeout=12, method="GET")
        self.assertEqual(result["investigation_type"], "website_login_surface_assessment")
        self.assertIn("hydra_style_note", result)

    def test_phone_number_metadata_recognises_ghana_calling_code(self):
        result = cyberlab.analyse_phone_number_metadata("+233201234567")
        self.assertEqual(result["country_calling_code"], "+233")
        self.assertEqual(result["numbering_region_reference"], "Ghana")

    def test_phone_number_metadata_parses_nigerian_country_code(self):
        result = cyberlab.analyse_phone_number_metadata("+234 801-234-5678")
        self.assertEqual(result["country_calling_code"], "+234")
        self.assertEqual(result["numbering_region_reference"], "Nigeria")
        self.assertIn("not publicly discoverable", result["registration_date"].lower())

    def test_phone_number_metadata_requires_international_prefix(self):
        with self.assertRaisesRegex(ValueError, "Include the international country code"):
            cyberlab.analyse_phone_number_metadata("08012345678")

    def test_phone_number_metadata_rejects_unrecognised_country_code(self):
        with self.assertRaisesRegex(ValueError, "not in CyberLab's built-in reference list"):
            cyberlab.analyse_phone_number_metadata("+999123456789")



    def test_credential_guess_lab_matches_only_local_synthetic_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "candidates.txt"
            wordlist.write_text("incorrect\nsecond-guess\nLabOnly-Password-42!\n", encoding="utf-8")
            progress = []
            result = cyberlab.run_credential_guess_lab(
                "demo-user", "LabOnly-Password-42!", wordlist,
                progress_callback=lambda count, status: progress.append((count, status)))
        self.assertTrue(result["candidate_match"])
        self.assertEqual(result["match_position"], 3)
        self.assertEqual(result["candidates_checked"], 3)
        self.assertEqual(result["network_requests_made"], 0)
        self.assertFalse(result["real_accounts_contacted"])
        self.assertNotIn("LabOnly-Password-42!", json.dumps(result))
        self.assertTrue(progress)

    def test_credential_guess_lab_mfa_still_required_after_password_match(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "candidates.txt"
            wordlist.write_text("Synthetic-Secret-77!\n", encoding="utf-8")
            result = cyberlab.run_credential_guess_lab(
                "demo-user", "Synthetic-Secret-77!", wordlist, mfa_enabled=True)
        self.assertEqual(result["simulated_outcome"], "password matched; MFA would still be required")

    def test_credential_guess_lab_rejects_symlink_wordlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual.txt"
            actual.write_text("secret\n", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(actual)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                cyberlab.run_credential_guess_lab("demo", "secret", link)

    def test_credential_guess_lab_enforces_attempt_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "candidates.txt"
            wordlist.write_text("a\nb\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "1-50,000"):
                cyberlab.run_credential_guess_lab("demo", "secret", wordlist, max_attempts=50001)

    def test_username_privacy_review_does_not_enumerate_accounts(self):
        result = cyberlab.assess_username_quality("abel1998_234801234567")
        self.assertTrue(result["risk_signals"]["contains_birth_year_like_sequence"])
        self.assertFalse(result["account_existence_checked"])

    def test_password_policy_review_reports_short_minimum(self):
        result = cyberlab.review_password_policy(8, "no", "unknown", "yes")
        self.assertEqual(result["controls"]["minimum_length"]["status"], "review")
        self.assertEqual(result["controls"]["breached_password_blocklist"], "no")

    def test_mfa_review_reports_missing_controls(self):
        result = cyberlab.review_mfa_controls("yes", "no", "unknown", "no")
        self.assertIn("phishing_resistant_factor_available", result["reported_gaps"])
        self.assertIn("recovery_and_reset_protected", result["unknown_controls"])


if __name__ == "__main__":
    unittest.main()
