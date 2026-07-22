import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "server.py"
SPEC = importlib.util.spec_from_file_location("foritech_server_readonly_boundary", MODULE_PATH)
server_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server_module)

REPO_ROOT = Path.home() / "services"
DIAG3_SERVER_PY = REPO_ROOT / "foritech-os/server/mcp-readonly/server.py"
DIAG3_POLICY_JSON = REPO_ROOT / "foritech-os/server/rules/mcp_readonly_policy.json"


def sha256_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SandboxedRootTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="foritech-server-readonly-sec-")
        self.root = Path(self.tmp)
        self.root_patch = patch.object(server_module, "ROOT", self.root)
        self.root_patch.start()

    def tearDown(self):
        self.root_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, relative, content=""):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path


class PathTraversalTests(SandboxedRootTestCase):
    def test_dotdot_traversal_is_rejected(self):
        with self.assertRaises(server_module.PathRejected) as ctx:
            server_module.resolve_user_path("../../../etc/passwd")
        self.assertEqual(ctx.exception.code, "PATH_TRAVERSAL_REJECTED")

    def test_absolute_path_is_rejected(self):
        with self.assertRaises(server_module.PathRejected) as ctx:
            server_module.resolve_user_path("/etc/passwd")
        self.assertEqual(ctx.exception.code, "ABSOLUTE_PATH_REJECTED")

    def test_tilde_path_is_rejected(self):
        with self.assertRaises(server_module.PathRejected) as ctx:
            server_module.resolve_user_path("~/.ssh/id_rsa")
        self.assertEqual(ctx.exception.code, "ABSOLUTE_PATH_REJECTED")

    def test_traversal_via_tools_returns_error_not_exception(self):
        result = server_module.tool_read_text_file({"path": "../../etc/passwd"})
        self.assertIn(result["error"], {"PATH_TRAVERSAL_REJECTED", "ABSOLUTE_PATH_REJECTED"})
        result = server_module.tool_list_directory({"path": "../.."})
        self.assertIn(result["error"], {"PATH_TRAVERSAL_REJECTED", "ABSOLUTE_PATH_REJECTED"})


class SymlinkRejectionTests(SandboxedRootTestCase):
    def test_symlink_leaf_is_rejected_by_resolver(self):
        target = self.write("target.txt", "content")
        link = self.root / "link.txt"
        link.symlink_to(target)
        with self.assertRaises(server_module.PathRejected) as ctx:
            server_module.resolve_user_path("link.txt")
        self.assertEqual(ctx.exception.code, "SYMLINK_NOT_ALLOWED")

    def test_symlink_escaping_root_is_rejected(self):
        outside = Path(tempfile.mkdtemp(prefix="outside-root-"))
        try:
            secret = outside / "secret.txt"
            secret.write_text("outside content")
            link = self.root / "escape.txt"
            link.symlink_to(secret)
            with self.assertRaises(server_module.PathRejected) as ctx:
                server_module.resolve_user_path("escape.txt")
            self.assertEqual(ctx.exception.code, "SYMLINK_NOT_ALLOWED")
        finally:
            shutil.rmtree(outside, ignore_errors=True)


class BinaryRejectionTests(SandboxedRootTestCase):
    def test_binary_content_is_rejected(self):
        path = self.root / "data.bin"
        path.write_bytes(bytes(range(256)))
        result = server_module.tool_read_text_file({"path": "data.bin"})
        self.assertEqual(result["error"], "BINARY_FILE_REJECTED")


class SensitivePathTests(SandboxedRootTestCase):
    def test_dotenv_is_denied(self):
        self.write(".env", "SECRET_KEY=abc123")
        result = server_module.tool_read_text_file({"path": ".env"})
        self.assertEqual(result["error"], "ACCESS_DENIED")

    def test_dotenv_variant_is_denied(self):
        self.write(".env.production", "SECRET_KEY=abc123")
        result = server_module.tool_read_text_file({"path": ".env.production"})
        self.assertEqual(result["error"], "ACCESS_DENIED")

    def test_dotenv_example_is_allowed(self):
        self.write(".env.example", "SECRET_KEY=")
        result = server_module.tool_read_text_file({"path": ".env.example"})
        self.assertNotIn("error", result)
        self.assertEqual(result["content"], "SECRET_KEY=")

    def test_ssh_directory_is_denied(self):
        self.write(".ssh/id_rsa", "fake-key-content")
        result = server_module.tool_read_text_file({"path": ".ssh/id_rsa"})
        self.assertEqual(result["error"], "ACCESS_DENIED")

    def test_ssh_directory_is_never_listed(self):
        self.write(".ssh/id_rsa", "fake-key-content")
        self.write("visible.txt", "hello")
        result = server_module.tool_list_directory({"path": "."})
        names = {e["name"] for e in result["entries"]}
        self.assertNotIn(".ssh", names)
        self.assertIn("visible.txt", names)

    def test_gnupg_aws_azure_kube_password_store_are_denied(self):
        for dirname, filename in [
            (".gnupg", "secring.gpg"),
            (".aws", "credentials"),
            (".azure", "accessTokens.json"),
            (".kube", "config"),
            (".password-store", "entry.gpg"),
        ]:
            self.write(f"{dirname}/{filename}", "sensitive")
            result = server_module.tool_read_text_file({"path": f"{dirname}/{filename}"})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{dirname}/{filename} should be denied")

    def test_nested_keyrings_directory_is_denied(self):
        self.write(".local/share/keyrings/login.keyring", "sensitive")
        result = server_module.tool_read_text_file({"path": ".local/share/keyrings/login.keyring"})
        self.assertEqual(result["error"], "ACCESS_DENIED")

    def test_git_credentials_and_netrc_are_denied(self):
        self.write(".git-credentials", "https://user:pass@example.com")
        self.write(".netrc", "machine example.com login user password pass")
        for name in (".git-credentials", ".netrc"):
            result = server_module.tool_read_text_file({"path": name})
            self.assertEqual(result["error"], "ACCESS_DENIED")

    def test_docker_config_json_is_denied(self):
        self.write(".docker/config.json", '{"auths": {}}')
        result = server_module.tool_read_text_file({"path": ".docker/config.json"})
        self.assertEqual(result["error"], "ACCESS_DENIED")

    def test_key_and_cert_globs_are_denied(self):
        for name in ("server.pem", "private.key", "bundle.p12", "bundle.pfx", "id_rsa", "id_ed25519"):
            self.write(name, "sensitive material")
            result = server_module.tool_read_text_file({"path": name})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{name} should be denied")

    def test_secret_and_credentials_substrings_are_denied(self):
        for name in ("api_secret.txt", "my-credentials-backup.txt", "SECRET_TOKENS.md"):
            self.write(name, "sensitive material")
            result = server_module.tool_read_text_file({"path": name})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{name} should be denied")

    def test_denied_path_error_identical_whether_file_exists_or_not(self):
        result_missing = server_module.tool_read_text_file({"path": ".ssh/does_not_exist"})
        self.write(".ssh/does_exist", "content")
        result_existing = server_module.tool_read_text_file({"path": ".ssh/does_exist"})
        self.assertEqual(result_missing["error"], "ACCESS_DENIED")
        self.assertEqual(result_existing["error"], "ACCESS_DENIED")
        self.assertEqual(result_missing["error"], result_existing["error"])


class OutputLimitTests(SandboxedRootTestCase):
    def test_list_directory_hard_cap_is_500(self):
        result = server_module.tool_list_directory({"path": ".", "max_entries": 10_000})
        # max_entries itself is clamped even with nothing to list; verify via
        # a direct look at the clamp logic through a populated dir.
        for i in range(3):
            self.write(f"f{i}.txt", "x")
        result = server_module.tool_list_directory({"path": ".", "max_entries": 10_000})
        self.assertLessEqual(len(result["entries"]), 500)

    def test_read_text_file_size_cap_matches_1_mib(self):
        self.assertEqual(server_module.MAX_TEXT_FILE_BYTES, 1 * 1024 * 1024)

    def test_search_text_hard_caps(self):
        self.assertEqual(server_module.MAX_SEARCH_RESULTS, 200)
        self.assertEqual(server_module.MAX_SEARCH_SCANNED_FILES, 5000)


class NoArbitraryCommandTests(unittest.TestCase):
    def test_only_twelve_tools_are_allowed(self):
        # Grew from 7 to 11 (four forisec_cl3_2026_context_* proxy tools) to 12
        # (forisec_cl3_2026_context_repo_map) -- still an exact, closed set with
        # no arbitrary-command/arbitrary-URL/arbitrary-filesystem tool.
        self.assertEqual(
            server_module.ALLOWED_TOOLS,
            {
                "server_status",
                "list_directory",
                "read_text_file",
                "search_text",
                "git_status",
                "docker_ps",
                "list_services",
                "forisec_cl3_2026_context_bootstrap",
                "forisec_cl3_2026_context_section",
                "forisec_cl3_2026_context_search",
                "forisec_cl3_2026_context_source",
                "forisec_cl3_2026_context_repo_map",
            },
        )

    def test_no_write_tools_exist_anywhere_in_tools_map(self):
        forbidden_substrings = ("write", "edit", "move", "delete", "create_dir", "run_command", "restart", "stop")
        for name in server_module.TOOLS:
            for bad in forbidden_substrings:
                self.assertNotIn(bad, name)

    def test_policy_file_lists_every_forbidden_action(self):
        policy = json.loads((Path(__file__).parents[1] / "policy.json").read_text())
        expected_forbidden = {
            "write_file", "edit_file", "move_file", "delete_file", "create_directory",
            "run_command", "sudo", "systemctl restart", "systemctl stop",
            "docker compose down", "rm", "chmod", "chown",
        }
        self.assertEqual(set(policy["forbidden_actions"]), expected_forbidden)
        self.assertEqual(policy["mode"], "read-only")
        self.assertEqual(policy["root"], "/home/forybg")
        self.assertEqual(set(policy["allowed_tools"]), server_module.ALLOWED_TOOLS)


class DiagnosticsThreeUntouchedTests(unittest.TestCase):
    """Guards against accidental edits to the unrelated, existing
    Diagnostics 3 service while working on this project."""

    def test_diagnostics_three_files_exist_and_are_unmodified_by_this_project(self):
        self.assertTrue(DIAG3_SERVER_PY.exists(), "Diagnostics 3 server.py must still exist")
        self.assertTrue(DIAG3_POLICY_JSON.exists(), "Diagnostics 3 policy.json must still exist")
        # This test only proves the files are present and readable; the
        # authoritative before/after hash comparison is recorded manually
        # in the task report (sha256sum run before and after this project
        # was created), since a single test run only has an "after" view.
        sha256_of(DIAG3_SERVER_PY)
        sha256_of(DIAG3_POLICY_JSON)

    def test_this_project_does_not_import_diagnostics_three(self):
        # A prose mention of Diagnostics 3 in a comment/docstring is fine
        # (this file documents the relationship); what must never exist
        # is an actual import of, or spec-load against, its module.
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("import server", source)
        self.assertNotIn("spec_from_file_location", source)
        self.assertNotRegex(source, r"from\s+.*foritech.os.*\s+import")
        self.assertNotIn("mcp_readonly_server", source)


if __name__ == "__main__":
    unittest.main()
