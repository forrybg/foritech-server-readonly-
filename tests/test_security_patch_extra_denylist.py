import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "server.py"
SPEC = importlib.util.spec_from_file_location("foritech_server_readonly_extra_deny", MODULE_PATH)
server_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server_module)


class SandboxedRootTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="foritech-server-readonly-extra-deny-")
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


class NewDeniedDirectoryTests(SandboxedRootTestCase):
    def test_new_denied_dirs_are_not_listed(self):
        for dirname in (".config", ".cache", ".step", ".foritech"):
            self.write(f"{dirname}/some_file.json", "data")
        self.write("visible.txt", "hello")

        result = server_module.tool_list_directory({"path": "."})
        names = {e["name"] for e in result["entries"]}
        for dirname in (".config", ".cache", ".step", ".foritech"):
            self.assertNotIn(dirname, names)
        self.assertIn("visible.txt", names)

    def test_new_denied_dirs_reject_direct_read(self):
        for dirname in (".config", ".cache", ".step", ".foritech"):
            path = self.write(f"{dirname}/some_file.json", "data")
            rel = f"{dirname}/some_file.json"
            result = server_module.tool_read_text_file({"path": rel})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{rel} should be denied")

    def test_search_text_skips_new_denied_dirs(self):
        self.write(".config/app/settings.json", "needle-value-here")
        self.write(".cache/blob.txt", "needle-value-here")
        self.write(".step/certs/needle.pem", "needle-value-here")
        self.write(".foritech/state.json", "needle-value-here")
        self.write("normal.txt", "needle-value-here")

        result = server_module.tool_search_text({"root": ".", "query": "needle-value-here"})
        paths = [r["path"] for r in result["results"]]
        self.assertEqual(paths, ["normal.txt"])

    def test_git_status_rejects_repo_under_denied_directory(self):
        repo_dir = self.root / ".config" / "somerepo"
        repo_dir.mkdir(parents=True)
        subprocess.run([server_module.GIT_BIN, "init", "-q", str(repo_dir)], check=True)
        result = server_module.tool_git_status({"path": ".config/somerepo"})
        self.assertEqual(result["error"], "ACCESS_DENIED")


class NewDeniedExactFileTests(SandboxedRootTestCase):
    EXACT_FILES = (
        ".bash_history",
        ".python_history",
        ".github_token",
        ".npmrc",
        ".pypirc",
        ".Xauthority",
        ".foritech_device",
    )

    def test_exact_files_are_not_listed(self):
        for name in self.EXACT_FILES:
            self.write(name, "sensitive")
        self.write("visible.txt", "hello")

        result = server_module.tool_list_directory({"path": "."})
        names = {e["name"] for e in result["entries"]}
        for name in self.EXACT_FILES:
            self.assertNotIn(name, names)
        self.assertIn("visible.txt", names)

    def test_exact_files_reject_direct_read(self):
        for name in self.EXACT_FILES:
            self.write(name, "sensitive")
            result = server_module.tool_read_text_file({"path": name})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{name} should be denied")

    def test_exact_files_skipped_by_search(self):
        for name in self.EXACT_FILES:
            self.write(name, "needle-marker")
        self.write("normal.txt", "needle-marker")

        result = server_module.tool_search_text({"root": ".", "query": "needle-marker"})
        paths = [r["path"] for r in result["results"]]
        self.assertEqual(paths, ["normal.txt"])

    def test_access_denied_identical_whether_file_exists_or_not(self):
        result_missing = server_module.tool_read_text_file({"path": ".github_token"})
        self.write(".npmrc", "registry=https://example.com/")
        result_existing = server_module.tool_read_text_file({"path": ".npmrc"})
        self.assertEqual(result_missing["error"], "ACCESS_DENIED")
        self.assertEqual(result_existing["error"], "ACCESS_DENIED")


class NewDeniedGlobTests(SandboxedRootTestCase):
    def test_token_glob_is_case_insensitive(self):
        for name in ("api_token.txt", "API_TOKEN.TXT", "MyTokenFile.json", "session-Token-backup.log"):
            self.write(name, "sensitive")
            result = server_module.tool_read_text_file({"path": name})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{name} should be denied")

    def test_history_glob_is_case_insensitive(self):
        for name in ("shell_HISTORY.log", "History.txt", "command_history_backup"):
            self.write(name, "sensitive")
            result = server_module.tool_read_text_file({"path": name})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{name} should be denied")

    def test_kdbx_and_ovpn_are_denied(self):
        for name in ("vault.kdbx", "VAULT.KDBX", "office.ovpn", "OFFICE.OVPN"):
            self.write(name, "sensitive")
            result = server_module.tool_read_text_file({"path": name})
            self.assertEqual(result["error"], "ACCESS_DENIED", f"{name} should be denied")

    def test_token_and_history_globs_skipped_by_list_and_search(self):
        self.write("my_token_backup.txt", "needle-marker")
        self.write("bash_HISTORY_export.log", "needle-marker")
        self.write("normal.txt", "needle-marker")

        listing = server_module.tool_list_directory({"path": "."})
        names = {e["name"] for e in listing["entries"]}
        self.assertNotIn("my_token_backup.txt", names)
        self.assertNotIn("bash_HISTORY_export.log", names)
        self.assertIn("normal.txt", names)

        result = server_module.tool_search_text({"root": ".", "query": "needle-marker"})
        paths = [r["path"] for r in result["results"]]
        self.assertEqual(paths, ["normal.txt"])


class ExistingBehaviorPreservedTests(SandboxedRootTestCase):
    def test_env_example_remains_allowed(self):
        self.write(".env.example", "MCP_SERVER_READONLY_BEARER_TOKEN=")
        result = server_module.tool_read_text_file({"path": ".env.example"})
        self.assertNotIn("error", result)
        self.assertEqual(result["content"], "MCP_SERVER_READONLY_BEARER_TOKEN=")

    def test_env_example_is_listed(self):
        self.write(".env.example", "X=")
        result = server_module.tool_list_directory({"path": "."})
        names = {e["name"] for e in result["entries"]}
        self.assertIn(".env.example", names)

    def test_normal_project_directories_remain_accessible(self):
        for dirname in ("code", "services", "infra"):
            self.write(f"{dirname}/readme.txt", "hello from " + dirname)

        listing = server_module.tool_list_directory({"path": "."})
        names = {e["name"] for e in listing["entries"]}
        for dirname in ("code", "services", "infra"):
            self.assertIn(dirname, names)

        for dirname in ("code", "services", "infra"):
            result = server_module.tool_read_text_file({"path": f"{dirname}/readme.txt"})
            self.assertNotIn("error", result)
            self.assertEqual(result["content"], "hello from " + dirname)

        result = server_module.tool_search_text({"root": ".", "query": "hello from"})
        paths = {r["path"] for r in result["results"]}
        self.assertEqual(paths, {"code/readme.txt", "services/readme.txt", "infra/readme.txt"})


if __name__ == "__main__":
    unittest.main()
