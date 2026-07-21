import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "server.py"
SPEC = importlib.util.spec_from_file_location("foritech_server_readonly_tools", MODULE_PATH)
server_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server_module)


class SandboxedRootTestCase(unittest.TestCase):
    """Every test in this file runs against a throwaway directory tree,
    patched in as ROOT, so nothing here ever touches the real
    /home/forybg or requires special fixture files to already exist."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="foritech-server-readonly-test-")
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


class ServerStatusTests(SandboxedRootTestCase):
    def test_server_status_has_expected_shape(self):
        result = server_module.tool_server_status({})
        self.assertIn("hostname", result)
        self.assertIn("uptime_seconds", result)
        self.assertIn("loadavg", result)
        self.assertIn("disk_root", result)
        self.assertIn("memory", result)
        self.assertIn("total_gb", result["disk_root"])


class ListDirectoryTests(SandboxedRootTestCase):
    def test_normal_directory_listing(self):
        self.write("alpha.txt", "a")
        self.write("beta.txt", "b")
        (self.root / "sub").mkdir()
        result = server_module.tool_list_directory({"path": "."})
        names = sorted(e["name"] for e in result["entries"])
        self.assertEqual(names, ["alpha.txt", "beta.txt", "sub"])
        self.assertFalse(result["truncated"])

    def test_output_is_bounded(self):
        for i in range(20):
            self.write(f"file_{i:03d}.txt", "x")
        result = server_module.tool_list_directory({"path": ".", "max_entries": 5})
        self.assertEqual(len(result["entries"]), 5)
        self.assertTrue(result["truncated"])

    def test_output_is_sorted(self):
        self.write("zebra.txt", "z")
        self.write("apple.txt", "a")
        self.write("mango.txt", "m")
        result = server_module.tool_list_directory({"path": "."})
        names = [e["name"] for e in result["entries"]]
        self.assertEqual(names, sorted(names))

    def test_symlinked_directory_target_is_rejected(self):
        target = self.root / "real_dir"
        target.mkdir()
        link = self.root / "link_dir"
        link.symlink_to(target, target_is_directory=True)
        result = server_module.tool_list_directory({"path": "link_dir"})
        self.assertEqual(result["error"], "SYMLINK_NOT_ALLOWED")

    def test_symlink_entries_are_listed_as_symlink_type_not_followed(self):
        real = self.write("real.txt", "hello")
        link = self.root / "link.txt"
        link.symlink_to(real)
        result = server_module.tool_list_directory({"path": "."})
        by_name = {e["name"]: e for e in result["entries"]}
        self.assertEqual(by_name["link.txt"]["type"], "symlink")


class ReadTextFileTests(SandboxedRootTestCase):
    def test_normal_text_reading(self):
        self.write("notes.txt", "hello world\nsecond line\n")
        result = server_module.tool_read_text_file({"path": "notes.txt"})
        self.assertEqual(result["content"], "hello world\nsecond line")

    def test_binary_file_is_rejected(self):
        path = self.root / "binary.bin"
        path.write_bytes(b"\x00\x01\x02\xff\xfe")
        result = server_module.tool_read_text_file({"path": "binary.bin"})
        self.assertEqual(result["error"], "BINARY_FILE_REJECTED")

    def test_oversized_file_is_rejected(self):
        path = self.root / "big.txt"
        path.write_text("x" * (server_module.MAX_TEXT_FILE_BYTES + 10))
        result = server_module.tool_read_text_file({"path": "big.txt"})
        self.assertEqual(result["error"], "FILE_TOO_LARGE")

    def test_symlinked_file_is_rejected(self):
        real = self.write("real2.txt", "content")
        link = self.root / "link2.txt"
        link.symlink_to(real)
        result = server_module.tool_read_text_file({"path": "link2.txt"})
        self.assertEqual(result["error"], "SYMLINK_NOT_ALLOWED")

    def test_missing_file_reports_not_found(self):
        result = server_module.tool_read_text_file({"path": "does-not-exist.txt"})
        self.assertEqual(result["error"], "PATH_NOT_FOUND")


class SearchTextTests(SandboxedRootTestCase):
    def test_literal_search_finds_matches(self):
        self.write("a.txt", "the quick brown fox\nsecond line with fox\n")
        self.write("b.txt", "no match here\n")
        result = server_module.tool_search_text({"root": ".", "query": "fox"})
        self.assertEqual(len(result["results"]), 2)
        self.assertTrue(all("fox" in r["text"] for r in result["results"]))

    def test_search_is_literal_not_regex(self):
        self.write("a.txt", "price is 3.14 dollars\nnot 3x14 anything\n")
        result = server_module.tool_search_text({"root": ".", "query": "3.14"})
        # a regex '.' would also match "3x14"; literal search must not.
        self.assertEqual(len(result["results"]), 1)
        self.assertIn("3.14", result["results"][0]["text"])

    def test_search_respects_max_results(self):
        content = "\n".join(f"needle number {i}" for i in range(50))
        self.write("many.txt", content)
        result = server_module.tool_search_text({"root": ".", "query": "needle", "max_results": 10})
        self.assertEqual(len(result["results"]), 10)
        self.assertTrue(result["truncated_results"])

    def test_search_respects_max_files_scanned(self):
        for i in range(20):
            self.write(f"file_{i:03d}.txt", "needle present here\n")
        result = server_module.tool_search_text({"root": ".", "query": "needle", "max_files": 5})
        self.assertLessEqual(result["files_scanned"], 5)
        self.assertTrue(result["truncated_scan"])

    def test_search_never_uses_shell_or_subprocess(self):
        self.write("a.txt", "needle\n")
        with patch("subprocess.run", side_effect=AssertionError("search_text must not call subprocess")):
            with patch("subprocess.Popen", side_effect=AssertionError("search_text must not call subprocess")):
                result = server_module.tool_search_text({"root": ".", "query": "needle"})
        self.assertEqual(len(result["results"]), 1)

    def test_search_skips_denied_paths(self):
        self.write(".ssh/id_rsa", "fake-private-key-needle")
        self.write("normal.txt", "needle in normal file")
        result = server_module.tool_search_text({"root": ".", "query": "needle"})
        paths = [r["path"] for r in result["results"]]
        self.assertNotIn(".ssh/id_rsa", paths)
        self.assertIn("normal.txt", paths)


class GitStatusTests(SandboxedRootTestCase):
    def _init_repo(self):
        subprocess.run(
            [server_module.GIT_BIN, "init", "-q", str(self.root / "repo")],
            check=True,
        )
        subprocess.run(
            [server_module.GIT_BIN, "-C", str(self.root / "repo"), "config", "user.email", "t@example.com"],
            check=True,
        )
        subprocess.run(
            [server_module.GIT_BIN, "-C", str(self.root / "repo"), "config", "user.name", "Test"],
            check=True,
        )

    def test_git_status_on_real_repo(self):
        self._init_repo()
        (self.root / "repo" / "tracked.txt").write_text("hello")
        result = server_module.tool_git_status({"path": "repo"})
        self.assertTrue(result.get("ok"))
        self.assertIn("lines", result)

    def test_git_status_on_non_repo_is_rejected(self):
        (self.root / "plain").mkdir()
        result = server_module.tool_git_status({"path": "plain"})
        self.assertEqual(result["error"], "NOT_A_GIT_REPOSITORY")

    def test_git_status_uses_fixed_argv_and_shell_false(self):
        self._init_repo()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="", stderr="")
            server_module.tool_git_status({"path": "repo"})
            args, kwargs = mock_run.call_args
            self.assertEqual(
                args[0],
                [server_module.GIT_BIN, "-C", str(self.root / "repo"), "status", "--short", "--branch"],
            )
            self.assertFalse(kwargs.get("shell", False))


class DockerPsAndListServicesTests(unittest.TestCase):
    def test_docker_ps_uses_fixed_argv_and_shell_false(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")
            server_module.tool_docker_ps({})
            args, kwargs = mock_run.call_args
            self.assertEqual(args[0], [server_module.DOCKER_BIN, "ps", "--format", "{{json .}}"])
            self.assertFalse(kwargs.get("shell", False))

    def test_list_services_uses_fixed_argv_and_shell_false(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["systemctl"], returncode=0, stdout="unit.service loaded active running\n", stderr=""
            )
            result = server_module.tool_list_services({})
            args, kwargs = mock_run.call_args
            self.assertEqual(
                args[0],
                [server_module.SYSTEMCTL_BIN, "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            )
            self.assertFalse(kwargs.get("shell", False))
            self.assertTrue(result["ok"])

    def test_no_tool_ever_passes_shell_true(self):
        # Static check across every tool implementation's use of subprocess.
        import inspect
        source = inspect.getsource(server_module)
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
