import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import urllib.request
import urllib.error

OLLAMA_URL = "http://localhost:11434/api/generate"

PLANNER_MODEL = "llama3.2"
POLICY_MODEL = "llama3.2"
TRIAGE_MODEL = "llama3.2"

WORKDIR = Path("devsecops_workdir")


def call_ollama(model: str, prompt: str) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = resp.read().decode("utf-8")
        parsed = json.loads(body)
        return parsed.get("response", "").strip()


def run_command(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def is_git_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://") or value.endswith(".git")


def clone_or_copy_repo(source: str, dest_root: Path) -> Path:
    dest_root.mkdir(parents=True, exist_ok=True)

    if is_git_url(source):
        repo_name = Path(urlparse(source).path).stem or "repo"
        dest = dest_root / repo_name
        code, out, err = run_command(["git", "clone", "--depth", "1", source, str(dest)])
        if code != 0:
            raise RuntimeError(f"git clone failed for {source}\n{err or out}")
        return dest

    src_path = Path(source).expanduser().resolve()
    if not src_path.exists():
        raise RuntimeError(f"Local path not found: {src_path}")

    dest = dest_root / src_path.name
    if src_path.is_dir():
        shutil.copytree(src_path, dest)
    else:
        raise RuntimeError(f"Expected a directory, got file: {src_path}")
    return dest


def inventory_repo(repo_path: Path) -> dict:
    py_files = list(repo_path.rglob("*.py"))
    tf_files = list(repo_path.rglob("*.tf"))
    req_files = list(repo_path.rglob("requirements.txt"))
    pyproject_files = list(repo_path.rglob("pyproject.toml"))

    return {
        "repo_path": str(repo_path),
        "python_file_count": len(py_files),
        "terraform_file_count": len(tf_files),
        "has_requirements_txt": len(req_files) > 0,
        "has_pyproject_toml": len(pyproject_files) > 0,
    }


def build_planner_prompt(repo_inventory: list[dict]) -> str:
    return f"""
You are a DevSecOps Planner Agent.

Given the repo inventory below, write a short scan plan.
Focus on defensive code review and IaC security review.

Repo inventory:
{json.dumps(repo_inventory, indent=2)}

Return exactly this format:

PLAN_SUMMARY:
<short summary>

SCAN_STRATEGY:
- item
- item

PRIORITY_AREAS:
- item
- item
""".strip()


def build_policy_prompt(inventory: dict) -> str:
    return f"""
You are a Security Policy Agent.

Decide which security scanners should run for this repository.
Choose only from these tools:
- bandit
- semgrep
- checkov
- pip_audit

Rules:
- Run bandit only if Python files are present
- Run semgrep if Python or Terraform files are present
- Run checkov if Terraform files are present
- Run pip_audit only if requirements.txt or pyproject.toml is present
- Be conservative and practical

Repository inventory:
{json.dumps(inventory, indent=2)}

Return ONLY valid JSON in this exact structure:
{{
  "run_bandit": true,
  "run_semgrep": true,
  "run_checkov": false,
  "run_pip_audit": false,
  "reasoning": [
    "reason 1",
    "reason 2"
  ]
}}
""".strip()


def parse_json_or_fallback(text: str, fallback: dict) -> dict:
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            return json.loads(text[start:end + 1])
    except Exception:
        pass
    return fallback


def tool_installed(name: str) -> bool:
    return shutil.which(name) is not None


def run_bandit(repo_path: Path) -> dict:
    if not tool_installed("bandit"):
        return {"tool": "bandit", "status": "skipped", "reason": "bandit not installed"}

    code, out, err = run_command(["bandit", "-r", str(repo_path), "-f", "json"])
    text = out or err
    return {
        "tool": "bandit",
        "status": "ok" if code in (0, 1) else "error",
        "exit_code": code,
        "raw": text,
    }


def run_semgrep(repo_path: Path, config: str = "auto") -> dict:
    if not tool_installed("semgrep"):
        return {"tool": "semgrep", "status": "skipped", "reason": "semgrep not installed"}

    code, out, err = run_command(
        ["semgrep", "scan", "--config", config, "--json", str(repo_path)]
    )
    text = out or err
    return {
        "tool": "semgrep",
        "status": "ok" if code in (0, 1) else "error",
        "exit_code": code,
        "raw": text,
    }


def run_checkov(repo_path: Path) -> dict:
    if not tool_installed("checkov"):
        return {"tool": "checkov", "status": "skipped", "reason": "checkov not installed"}

    code, out, err = run_command(
        ["checkov", "-d", str(repo_path), "--framework", "terraform", "--output", "json"]
    )
    text = out or err
    return {
        "tool": "checkov",
        "status": "ok" if code in (0, 1) else "error",
        "exit_code": code,
        "raw": text,
    }


def run_pip_audit(repo_path: Path) -> dict:
    if not tool_installed("pip-audit"):
        return {"tool": "pip-audit", "status": "skipped", "reason": "pip-audit not installed"}

    requirements = repo_path / "requirements.txt"
    if requirements.exists():
        code, out, err = run_command(
            ["pip-audit", "-r", str(requirements), "--format", "json"]
        )
        text = out or err
        return {
            "tool": "pip-audit",
            "status": "ok" if code in (0, 1) else "error",
            "exit_code": code,
            "raw": text,
        }

    return {
        "tool": "pip-audit",
        "status": "skipped",
        "reason": "No requirements.txt found for this teaching version",
    }


def build_triage_prompt(repo_inventory: dict, tool_results: list[dict]) -> str:
    return f"""
You are a Security Triage Agent for an internal DevSecOps pipeline.

Your job:
- Read the scanner outputs
- Highlight the most important issues
- Separate likely signal from noise
- Recommend whether the repo should PASS, WARN, or FAIL the pipeline
- Keep the report useful for cloud/security engineers

Repository inventory:
{json.dumps(repo_inventory, indent=2)}

Scanner results:
{json.dumps(tool_results, indent=2)[:20000]}

Return exactly this format:

TRIAGE_SUMMARY:
<short summary>

TOP_FINDINGS:
- item
- item

LIKELY_NOISE:
- item
- item

PIPELINE_DECISION:
<PASS, WARN, or FAIL>

RECOMMENDED_NEXT_STEPS:
- item
- item
""".strip()


def save_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main():
    print("\n=== AI DevSecOps Repo Scanner ===\n")
    print("Only scan repositories you own or are explicitly authorized to assess.\n")

    raw_sources = input(
        "Enter local repo paths or authorized Git repo URLs, separated by commas:\n> "
    ).strip()
    if not raw_sources:
        print("No repos provided.")
        return

    sources = [s.strip() for s in raw_sources.split(",") if s.strip()]
    semgrep_config = input("Semgrep config (default: auto): ").strip() or "auto"

    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    WORKDIR.mkdir(parents=True, exist_ok=True)

    local_repos: list[Path] = []
    inventories: list[dict] = []

    print("\n--- Fetching repos ---")
    for src in sources:
        try:
            repo_path = clone_or_copy_repo(src, WORKDIR / "repos")
            local_repos.append(repo_path)
            inv = inventory_repo(repo_path)
            inventories.append(inv)
            print(f"Loaded: {repo_path}")
        except Exception as e:
            print(f"[ERROR] {src}: {e}")

    if not local_repos:
        print("No repos could be loaded.")
        return

    planner_prompt = build_planner_prompt(inventories)
    planner_output = call_ollama(PLANNER_MODEL, planner_prompt)
    print("\n--- Planner Agent ---\n")
    print(planner_output)
    save_text(WORKDIR / "planner_report.txt", planner_output)

    for repo_path, inv in zip(local_repos, inventories):
        print(f"\n{'=' * 20} REPO: {repo_path.name} {'=' * 20}")

        policy_prompt = build_policy_prompt(inv)
        policy_raw = call_ollama(POLICY_MODEL, policy_prompt)
        policy = parse_json_or_fallback(
            policy_raw,
            {
                "run_bandit": inv["python_file_count"] > 0,
                "run_semgrep": (inv["python_file_count"] > 0 or inv["terraform_file_count"] > 0),
                "run_checkov": inv["terraform_file_count"] > 0,
                "run_pip_audit": inv["has_requirements_txt"],
                "reasoning": ["Fallback policy used because JSON parsing failed."],
            },
        )

        print("\n--- Security Policy Agent ---\n")
        print(json.dumps(policy, indent=2))
        save_text(WORKDIR / f"{repo_path.name}_policy.json", json.dumps(policy, indent=2))

        tool_results = []

        if policy.get("run_bandit"):
            tool_results.append(run_bandit(repo_path))

        if policy.get("run_semgrep"):
            tool_results.append(run_semgrep(repo_path, config=semgrep_config))

        if policy.get("run_checkov"):
            tool_results.append(run_checkov(repo_path))

        if policy.get("run_pip_audit"):
            tool_results.append(run_pip_audit(repo_path))

        save_text(
            WORKDIR / f"{repo_path.name}_scanner_results.json",
            json.dumps(tool_results, indent=2)
        )

        triage_prompt = build_triage_prompt(inv, tool_results)
        triage_output = call_ollama(TRIAGE_MODEL, triage_prompt)

        print("\n--- Security Triage Agent ---\n")
        print(triage_output)
        save_text(WORKDIR / f"{repo_path.name}_triage.txt", triage_output)

    print(f"\nDone. Reports saved under: {WORKDIR}\n")


if __name__ == "__main__":
    main()
