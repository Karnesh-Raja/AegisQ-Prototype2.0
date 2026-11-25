import io
import unittest
import zipfile

import app

class AegisQTests(unittest.TestCase):
    def setUp(self):
        app.app.config["TESTING"] = True
        self.client = app.app.test_client()

    def test_dashboard_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AEGISQ", response.data)

    def test_demo_finds_crypto_and_evidence(self):
        result = self.client.get("/api/demo")
        self.assertEqual(result.status_code, 200)
        data = result.get_json()
        self.assertGreater(data["summary"]["total"], 0)
        self.assertTrue(all(a["evidence"]["line"] > 0 for a in data["assets"]))
        self.assertTrue(all(a["data_lifetime_years"] > 0 for a in data["assets"]))
        self.assertIn("X.509", data["summary"]["algorithms"])
        self.assertIn("SLH-DSA (FIPS 205)", next(r["recommendation"] for r in data["recommendations"] if r["detected"] == "ECDSA"))
        self.assertTrue(all("confidence" in a and "mosca_total_years" in a for a in data["assets"]))
        self.assertTrue(data["recommendations"])

    def test_scenario_returns_bounded_urgency(self):
        result = self.client.post("/api/simulate", json={"x": 15, "y": 4, "z": 12})
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.get_json()["mosca_triggered"])
        self.assertEqual(result.get_json()["classical_x_plus_y"], 19)

    def test_threat_horizon_reassesses_findings(self):
        scan = self.client.get("/api/demo?z=12").get_json()
        result = self.client.post("/api/assess", json={"assets": scan["assets"], "z": 30}).get_json()
        self.assertEqual(result["summary"]["threat_horizon_years"], 30)
        self.assertGreaterEqual(scan["summary"]["critical"], result["summary"]["critical"])

    def test_report_download(self):
        result = self.client.get("/api/demo").get_json()
        response = self.client.post("/api/report", json=result)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")

    def test_zip_rejects_traversal(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("../escape.py", "RSA")
        response = self.client.post("/api/scan", data={"file": (io.BytesIO(buffer.getvalue()), "sample.zip")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn("unsafe", response.get_json()["error"])

    def test_zip_scans_text_without_execution(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("settings.py", 'CIPHER = "AES-256-GCM"\n')
            zf.writestr("run.exe", "RSA")
        response = self.client.post("/api/scan", data={"file": (io.BytesIO(buffer.getvalue()), "sample.zip")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([x["algorithm"] for x in response.get_json()["assets"]], ["AES"])

    def test_zip_detects_x509_certificate_reference(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("config/cert.yaml", "cert_file: server.crt\ncertificate_format: X.509\n")
        response = self.client.post("/api/scan", data={"file": (io.BytesIO(buffer.getvalue()), "sample.zip")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertIn("X.509", [a["algorithm"] for a in response.get_json()["assets"]])

    def test_zip_requires_a_file(self):
        response = self.client.post("/api/scan", data={}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__": unittest.main()
