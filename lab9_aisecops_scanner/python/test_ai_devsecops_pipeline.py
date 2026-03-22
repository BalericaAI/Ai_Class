import json
from pathlib import Path

import ai_devsecops_pipeline as pipeline


def test_inventory_repo_counts_python_and_terraform_files(tmp_path):
    repo = tmp_path / "repo1"
    repo.mkdir()

    (repo / "app.py").write_text("print('hello')", encoding="utf-8")
    (repo / "main.tf").write_text('resource "null_resource" "x" {}', encoding="utf-8")
    (repo / "requirements.txt").write_text("flask==2.0.0", encoding="utf-8")

    result = pipeline.inventory_repo(repo)

    assert result["python_file_count"] == 1
    assert result["terraform_file_count"] == 1
    assert result["has_requirements_txt"] is True
    assert result["has_pyproject_toml"] is False
    assert result["has_security_manifest"] is False


def test_load_security_manifest_returns_empty_when_missing(tmp_path):
    repo = tmp_path / "repo2"
    repo.mkdir()

    manifest = pipeline.load_security_manifest(repo)

    assert manifest == {"approved_scripts": []}


def test_load_security_manifest_reads_valid_json(tmp_path):
    repo = tmp_path / "repo3"
    repo.mkdir()

    manifest_data = {
        "approved_scripts": [
            {"path": "security/check_headers.py", "args": ["--mode", "audit"]}
        ]
    }

    (repo / "security_manifest.json").write_text(
        json.dumps(manifest_data),
        encoding="utf-8"
    )

    manifest = pipeline.load_security_manifest(repo)

    assert manifest["approved_scripts"][0]["path"] == "security/check_headers.py"
    assert manifest["approved_scripts"][0]["args"] == ["--mode", "audit"]


def test_parse_json_or_fallback_returns_parsed_json():
    fallback = {"run_bandit": False}
    text = """
    Here is your result:
    {
      "run_bandit": true,
      "run_semgrep": false
    }
    Thanks.
    """

    result = pipeline.parse_json_or_fallback(text, fallback)

    assert result["run_bandit"] is True
    assert result["run_semgrep"] is False


def test_parse_json_or_fallback_uses_fallback_on_bad_json():
    fallback = {"run_bandit": False, "reasoning": ["fallback used"]}
    text = "this is not valid json at all"

    result = pipeline.parse_json_or_fallback(text, fallback)

    assert result == fallback


def test_find_terraform_dir_returns_parent_of_tf_file(tmp_path):
    repo = tmp_path / "repo4"
    infra = repo / "infra"
    infra.mkdir(parents=True)

    (infra / "main.tf").write_text('resource "null_resource" "x" {}', encoding="utf-8")

    result = pipeline.find_terraform_dir(repo)

    assert result == infra


def test_find_terraform_dir_returns_none_when_no_tf_files(tmp_path):
    repo = tmp_path / "repo5"
    repo.mkdir()

    result = pipeline.find_terraform_dir(repo)

    assert result is None


def test_run_approved_scripts_skips_missing_script(tmp_path):
    repo = tmp_path / "repo6"
    repo.mkdir()

    manifest_data = {
        "approved_scripts": [
            {"path": "security/missing_script.py", "args": ["--mode", "audit"]}
        ]
    }

    (repo / "security_manifest.json").write_text(
        json.dumps(manifest_data),
        encoding="utf-8"
    )

    results = pipeline.run_approved_scripts(repo)

    assert len(results) == 1
    assert results[0]["tool"] == "custom_script"
    assert results[0]["status"] == "skipped"
    assert results[0]["reason"] == "Script not found"


def test_run_approved_scripts_blocks_path_escape(tmp_path):
    repo = tmp_path / "repo7"
    repo.mkdir()

    manifest_data = {
        "approved_scripts": [
            {"path": "../evil.py", "args": []}
        ]
    }

    (repo / "security_manifest.json").write_text(
        json.dumps(manifest_data),
        encoding="utf-8"
    )

    results = pipeline.run_approved_scripts(repo)

    assert len(results) == 1
    assert results[0]["status"] == "skipped"
    assert results[0]["reason"] == "Script path escapes repo root"


def test_run_approved_scripts_executes_valid_script(tmp_path, monkeypatch):
    repo = tmp_path / "repo8"
    security_dir = repo / "security"
    security_dir.mkdir(parents=True)

    script_path = security_dir / "check_headers.py"
    script_path.write_text(
        "print('audit ok')",
        encoding="utf-8"
    )

    manifest_data = {
        "approved_scripts": [
            {"path": "security/check_headers.py", "args": ["--mode", "audit"]}
        ]
    }

    (repo / "security_manifest.json").write_text(
        json.dumps(manifest_data),
        encoding="utf-8"
    )

    def fake_run_command(cmd, cwd=None):
        return 0, "audit ok", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)

    results = pipeline.run_approved_scripts(repo)

    assert len(results) == 1
    assert results[0]["status"] == "ok"
    assert results[0]["script"] == "security/check_headers.py"
    assert results[0]["stdout"] == "audit ok"


def test_build_triage_prompt_contains_inventory_and_results():
    inventory = {
        "repo_path": "/tmp/repo",
        "python_file_count": 2,
        "terraform_file_count": 1,
    }
    tool_results = [
        {"tool": "bandit", "status": "ok"},
        {"tool": "checkov_plan", "status": "ok"},
    ]

    prompt = pipeline.build_triage_prompt(inventory, tool_results)

    assert "Security Triage Agent" in prompt
    assert '"python_file_count": 2' in prompt
    assert '"tool": "bandit"' in prompt
    assert '"tool": "checkov_plan"' in prompt
    assert "PIPELINE_DECISION:" in prompt


def test_run_terraform_plan_security_skips_when_terraform_missing(monkeypatch, tmp_path):
    terraform_dir = tmp_path / "infra"
    terraform_dir.mkdir()

    monkeypatch.setattr(pipeline, "tool_installed", lambda name: False)

    results = pipeline.run_terraform_plan_security(terraform_dir)

    assert len(results) == 1
    assert results[0]["status"] == "skipped"
    assert results[0]["reason"] == "terraform not installed"
