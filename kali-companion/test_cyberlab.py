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

    def test_automated_url_assessment_checks_dns_tls_and_page_without_query_values(self):
        page = {"status_code": 200, "page_title": "Example", "authentication_analysis": {},
                "security_headers_missing": [], "cookies": []}
        dns = {"records": {"A": {"answers": [{"value": "93.184.216.34"}]}, "AAAA": {"answers": []}}}
        tls = {"status": "validated", "protocol": "TLSv1.3"}
        with patch.object(cyberlab, "_validate_assessment_url", return_value="https://example.test/"), \
             patch.object(cyberlab, "dns_lookup", return_value=dns) as dns_check, \
             patch.object(cyberlab, "_tls_certificate_summary", return_value=tls) as tls_check, \
             patch.object(cyberlab, "inspect_assessment_page", return_value=page) as page_check, \
             patch.dict(cyberlab.os.environ, {}, clear=True):
            result = cyberlab.automated_url_assessment("https://example.test/login?token=secret#frag")
        dns_check.assert_called_once()
        tls_check.assert_called_once_with("example.test", 443, 12)
        page_check.assert_called_once_with("https://example.test/login", timeout=12, method="GET")
        self.assertEqual(result["submitted_url"], "https://example.test/login")
        self.assertEqual(result["query_parameter_names"], ["token"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(result["http_page_inspection"]["status_code"], 200)

    def test_automated_url_assessment_blocks_private_destinations(self):
        with patch.object(cyberlab, "_validate_assessment_url",
                          side_effect=ValueError("non-public address")):
            result = cyberlab.automated_url_assessment("https://127.0.0.1/admin")
        self.assertEqual(result["assessment_status"], "blocked_for_safety")
        self.assertIn("non-public", result["error"])

    def test_safe_browsing_lookup_reports_match(self):
        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return b'{"matches":[{"threatType":"MALWARE","platformType":"ANY_PLATFORM"}]}'
        with patch.object(cyberlab.urllib.request, "urlopen", return_value=FakeResponse()):
            result = cyberlab._safe_browsing_url_lookup("https://example.test/path", "test-key")
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["matches"][0]["threat_type"], "MALWARE")

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

    def test_dns_intelligence_input_redacts_url_query_values(self):
        identity = cyberlab._normalise_osint_input("https://example.test/path?token=secret&next=%2Fhome#frag")
        self.assertNotIn("secret", repr(identity))
        self.assertNotIn("frag", repr(identity))
        self.assertIn("token=", identity["website_url"])

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
    def test_automated_assessment_uses_passive_evidence_without_checklist(self):
        page_result = {
            "status_code": 200,
            "login_classification": "email/password form pattern",
            "cookies": [{"secure": True, "httponly": True, "samesite": "Lax"}],
            "security_headers_missing": [],
            "security_headers": {},
            "response_headers": {"RateLimit-Limit": "10"},
            "visible_forms": [],
        }
        dns_result = {"records": {
            "MX": {"answers": [{"value": "mail.example.test"}]},
            "TXT": {"answers": [{"value": "v=spf1 -all"}]},
            "DMARC": {"answers": [{"value": "v=DMARC1; p=reject"}]},
        }}
        with patch("builtins.input", side_effect=["staging.example.test", "yes"]), \
             patch.object(cyberlab, "inspect_assessment_page", return_value=page_result) as inspect, \
             patch.object(cyberlab, "dns_lookup", return_value=dns_result):
            result = cyberlab.manual_security_assessment()
        self.assertTrue(result["authorisation_confirmed_by_operator"])
        self.assertEqual(result["target"], "staging.example.test")
        self.assertEqual(result["login_method"], "email/password form pattern")
        self.assertEqual(result["checks"]["session_secure"], "yes")
        self.assertEqual(result["checks"]["rate_limit"], "yes")
        self.assertEqual(result["checks"]["sql_parameter_binding"], "unknown")
        self.assertEqual(inspect.call_count, 1)
        self.assertEqual(inspect.call_args.kwargs["method"], "GET")
        self.assertIn("analysis", result)
        self.assertEqual(result["dns_inspection"], dns_result)

    def test_login_form_analysis_reports_action_method_csrf_and_autocomplete(self):
        forms = [{
            "method": "post", "action": "/session", "enctype": "application/x-www-form-urlencoded",
            "autocomplete": "off",
            "fields": [
                {"tag": "input", "type": "email", "name": "email", "autocomplete": "username", "required": True},
                {"tag": "input", "type": "password", "name": "password", "autocomplete": "current-password", "required": True},
                {"tag": "input", "type": "hidden", "name": "csrf_token", "autocomplete": "", "required": False},
            ],
        }]
        result = cyberlab._analyse_login_forms(forms, "https://example.test/login")
        self.assertEqual(result["authentication_form_count"], 1)
        form = result["forms_analysed"][0]
        self.assertEqual(form["method"], "POST")
        self.assertTrue(form["action_same_origin"])
        self.assertEqual(form["csrf_or_token_field_names"], ["csrf_token"])
        self.assertIn("current-password", form["autocomplete_values"])
        self.assertTrue(result["csrf_token_field_observed"])

    def test_login_form_analysis_flags_get_password_submission_pattern(self):
        forms = [{
            "method": "get", "action": "https://other.example.test/collect",
            "fields": [
                {"type": "text", "name": "username"},
                {"type": "password", "name": "password"},
            ],
        }]
        result = cyberlab._analyse_login_forms(forms, "https://example.test/login")
        form = result["forms_analysed"][0]
        self.assertFalse(form["action_same_origin"])
        self.assertIn("Authentication-like form uses GET", " ".join(form["security_observations"]))

    def test_page_metadata_parser_collects_scripts_and_auth_form_attributes(self):
        parser = cyberlab._PageMetadata()
        parser.feed('<title>Sign in</title><script src="/app.js"></script>'
                    '<form method="post" action="/session"><input type="password" '
                    'name="password" autocomplete="current-password" required></form>')
        self.assertEqual(parser.title, ["Sign in"])
        self.assertEqual(parser.scripts[0]["src"], "/app.js")
        self.assertEqual(parser.forms[0]["method"], "post")
        self.assertEqual(parser.forms[0]["fields"][0]["autocomplete"], "current-password")
        self.assertTrue(parser.forms[0]["fields"][0]["required"])

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

    def test_dns_intelligence_email_uses_email_specific_workflow(self):
        records = {"MX": {"answers": [{"value": "10 mx.example.org"}]},
                   "TXT": {"answers": [{"value": "v=spf1 -all"}]},
                   "DMARC": {"answers": [{"value": "v=DMARC1; p=reject"}]},
                   "CAA": {"answers": []}}
        with patch.object(cyberlab, "dns_lookup", return_value={"records": records}), \
             patch.object(cyberlab, "_dkim_selector_checks", return_value={"published_selectors_found": []}), \
             patch.object(cyberlab, "resolve_public_site_ips", return_value={"addresses": ["203.0.113.10"]}), \
             patch.object(cyberlab, "public_site_profile", return_value={"status": "ok", "organisation_name": "Example Org", "public_contact_emails": ["contact@example.org"], "public_contact_phone_numbers": ["+1 555 0100"], "social_media_links": ["https://linkedin.com/company/example"], "public_location": ["Lagos", '.href="/lander"}'], "public_address": []}), \
             patch.object(cyberlab, "_dns_passive_domain_assets", return_value={"status": "ok", "subdomains": [{"hostname": "www.example.org", "public_ip_addresses": ["203.0.113.11"]}], "public_ip_addresses": ["203.0.113.11"]}):
            result = cyberlab.dns_intelligence_lookup("person@example.org")
        self.assertEqual(result["investigation_type"], "email_intelligence")
        self.assertIn("email_intelligence", result)
        self.assertNotIn("sources", result)
        self.assertEqual(result["email_intelligence"]["submitted_email_address"], "person@example.org")
        associations = result["email_intelligence"]["public_domain_associations"]
        self.assertEqual(associations["organisation_name"], "Example Org")
        self.assertEqual(associations["public_business_phone_numbers"], ["+1 555 0100"])
        self.assertEqual(associations["public_social_media_links"], ["https://linkedin.com/company/example"])
        self.assertEqual(associations["public_social_account_identifiers"][0]["public_path_identifier"], "example")
        self.assertEqual(associations["public_ip_addresses"], ["203.0.113.10"])
        self.assertEqual(associations["certificate_transparency_assets"]["public_ip_addresses"], ["203.0.113.11"])
        self.assertEqual(associations["public_locations"], ["Lagos"])
        self.assertIn("does not establish", associations["relationship_note"])

    def test_dns_intelligence_social_profile_inspects_supplied_profile_not_homepage(self):
        with patch.object(cyberlab, "inspect_assessment_page", return_value={"status_code": 200, "page_title": "Example Profile"}) as inspect:
            result = cyberlab.dns_intelligence_lookup("https://facebook.com/example")
        self.assertEqual(result["investigation_type"], "social_profile_url_intelligence")
        self.assertEqual(result["social_profile_intelligence"]["platform"], "facebook.com")
        self.assertEqual(inspect.call_args.args[0], "https://facebook.com/example")
        self.assertNotIn("sources", result)

    def test_dns_intelligence_url_uses_url_specific_page_inspection(self):
        with patch.object(cyberlab, "_url_intelligence_findings", return_value={"enhanced_indicators": []}), \
             patch.object(cyberlab, "inspect_assessment_page", return_value={"status_code": 200, "page_title": "Example"}) as inspect:
            result = cyberlab.dns_intelligence_lookup("https://example.org/login")
        self.assertEqual(result["investigation_type"], "website_url_intelligence")
        self.assertIn("page_inspection", result["url_intelligence"])
        self.assertEqual(inspect.call_args.args[0], "https://example.org/login")


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


    def test_automated_password_audit_scans_and_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "settings.py").write_text(
                'USERNAME = "lab_operator"\nEMAIL = "security@example.test"\nPASSWORD = "QwErTy-Secret-9981!"\\n',
                encoding="utf-8")
            result = cyberlab.audit_password_security_target(directory)
        encoded = json.dumps(result)
        self.assertEqual(result["feature"], "automated_password_security_audit")
        self.assertEqual(result["scan_summary"]["files_scanned"], 1)
        self.assertEqual(result["scan_summary"]["email_addresses_found"], 1)
        self.assertEqual(result["scan_summary"]["username_values_found"], 1)
        self.assertEqual(result["scan_summary"]["literal_secret_candidates_found"], 1)
        self.assertNotIn("QwErTy-Secret-9981!", encoded)
        self.assertIn("security@example.test", encoded)
        self.assertIn("lab_operator", encoded)

    def test_automated_password_audit_uses_hibp_prefix_and_never_plaintext(self):
        secret = "BreachCandidate-Secret-2026!"
        suffix_hash = hashlib.sha1(secret.encode("utf-8")).hexdigest().upper()
        payload = (suffix_hash[5:] + ":42\n").encode("ascii")
        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size=-1): return payload
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.env").write_text(f'PASSWORD="{secret}"\n', encoding="utf-8")
            with patch.object(cyberlab.urllib.request, "urlopen", return_value=FakeResponse()) as mocked:
                result = cyberlab.audit_password_security_target(directory)
        request = mocked.call_args.args[0]
        self.assertTrue(request.full_url.endswith(suffix_hash[:5]))
        self.assertNotIn(secret, request.full_url)
        self.assertTrue(result["breached_password_checks"][0]["breached_password_match"])
        self.assertEqual(result["breached_password_checks"][0]["breach_corpus_occurrences"], 42)
        self.assertNotIn(secret, json.dumps(result))
        self.assertTrue(any(item["severity"] == "critical" for item in result["findings"]))

    def test_automated_password_audit_handles_hibp_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "settings.env").write_text('PASSWORD="SomeCandidateValue!"', encoding="utf-8")
            with patch.object(cyberlab.urllib.request, "urlopen", side_effect=OSError("offline")):
                result = cyberlab.audit_password_security_target(directory)
        self.assertEqual(result["breached_password_checks"][0]["status"], "unavailable")
        self.assertEqual(result["scan_summary"]["literal_secret_candidates_found"], 1)

    def test_password_policy_review_reports_short_minimum(self):
        result = cyberlab.review_password_policy(8, "no", "unknown", "yes")
        self.assertEqual(result["controls"]["minimum_length"]["status"], "review")
        self.assertEqual(result["controls"]["breached_password_blocklist"], "no")

    def test_mfa_target_assessment_checks_url_email_domain_and_page_evidence(self):
        page = {
            "status_code": 200, "page_title": "Sign in",
            "authentication_analysis": {"forms_analysed": [{
                "field_names": ["email", "password", "otp_code"],
                "input_types": ["email", "password", "one-time-code"]
            }]},
            "scripts": [{"url": "https://login.example.test/authenticator.js"}]
        }
        dns = {"records": {
            "MX": {"answers": [{"value": "mail.example.test"}]},
            "TXT": {"answers": [{"value": "v=spf1 -all"}]},
            "DMARC": {"answers": [{"value": "v=DMARC1; p=reject"}]}
        }}
        with patch.object(cyberlab, "_validate_assessment_url", return_value="https://login.example.test/signin"), \
             patch.object(cyberlab, "inspect_assessment_page", return_value=page) as inspect, \
             patch.object(cyberlab, "dns_lookup", return_value=dns) as dns_check:
            result = cyberlab.assess_mfa_target("https://login.example.test/signin",
                                                "abel@example.test")
        inspect.assert_called_once_with("https://login.example.test/signin", timeout=12, method="GET")
        dns_check.assert_called_once_with("example.test", timeout=12)
        self.assertEqual(result["target_url_checked"], "https://login.example.test/signin")
        self.assertEqual(result["email_address"], "a***@example.test")
        self.assertTrue(result["mfa_observations"]["visible_mfa_ui_indicators"])
        self.assertEqual(result["mfa_observations"]["account_mfa_enforcement"], "not_verifiable")
        self.assertEqual(result["findings"][1]["status"], "same_domain_or_parent_domain")

    def test_mfa_target_assessment_flags_email_domain_mismatch_and_does_not_claim_mfa(self):
        page = {"status_code": 200, "authentication_analysis": {"forms_analysed": []}, "scripts": []}
        dns = {"records": {"MX": {"answers": []}, "TXT": {"answers": []}, "DMARC": {"answers": []}}}
        with patch.object(cyberlab, "_validate_assessment_url", return_value="https://login.example.test/"), \
             patch.object(cyberlab, "inspect_assessment_page", return_value=page), \
             patch.object(cyberlab, "dns_lookup", return_value=dns):
            result = cyberlab.assess_mfa_target("https://login.example.test/", "user@other.test")
        self.assertEqual(result["findings"][1]["status"], "domain_mismatch_review")
        self.assertFalse(result["mfa_observations"]["visible_mfa_ui_indicators"])
        self.assertEqual(result["mfa_observations"]["account_mfa_enrollment"], "not_verifiable")
        self.assertNotIn("user@other.test", json.dumps(result))

    def test_mfa_target_assessment_rejects_invalid_email(self):
        with patch.object(cyberlab, "_validate_assessment_url", return_value="https://login.example.test/"):
            with self.assertRaisesRegex(ValueError, "valid email"):
                cyberlab.assess_mfa_target("https://login.example.test/", "not-an-email")


if __name__ == "__main__":
    unittest.main()
