import unittest

from src.secure_code_review import review_source


class TestSecureCodeReview(unittest.TestCase):
    def test_hardcoded_password(self):
        findings = review_source('password = "example123"')
        self.assertTrue(any(f.category == "Hardcoded credential" for f in findings))

    def test_possible_sql_injection(self):
        source = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = review_source(source)
        self.assertTrue(any(f.category == "Possible SQL injection" for f in findings))

    def test_risky_shell_execution(self):
        findings = review_source('subprocess.run(command, shell=True)')
        self.assertTrue(any(f.category == "Risky shell execution" for f in findings))

    def test_dynamic_code_execution(self):
        findings = review_source("result = eval(user_input)")
        self.assertTrue(any(f.category == "Dynamic code execution" for f in findings))

    def test_unsafe_deserialization(self):
        findings = review_source("data = pickle.loads(raw_data)")
        self.assertTrue(any(f.category == "Unsafe deserialization" for f in findings))

    def test_weak_hash_algorithm(self):
        findings = review_source("digest = hashlib.md5(data).hexdigest()")
        self.assertTrue(any(f.category == "Weak hash algorithm" for f in findings))

    def test_debug_mode(self):
        findings = review_source("app.run(debug=True)")
        self.assertTrue(any(f.category == "Debug mode enabled" for f in findings))

    def test_safe_basic_code(self):
        findings = review_source("total = 2 + 3\nprint(total)")
        self.assertEqual(findings, [])

    def test_finding_has_correct_line_number(self):
        source = "total = 2 + 3\npassword = 'example123'"
        findings = review_source(source)
        credential_findings = [
            f for f in findings if f.category == "Hardcoded credential"
        ]
        self.assertTrue(credential_findings)
        self.assertEqual(credential_findings[0].line, 2)


if __name__ == "__main__":
    unittest.main()
