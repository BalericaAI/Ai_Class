import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse
import urllib.request
import urllib.error

OLLAMA_URL = "http://localhost:11434/api/generate"

PLANNER_MODEL = "llama3.2"
POLICY_MODEL = "llama3.2"
TRIAGE_MODEL = "llama3.2"

WORKDIR = Path("ai_devsecops_workdir")


def call_ollama(model: str, prompt: str) -> str:
    payload = {"model": model, "prompt": prompt, "stream": False}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body).get("response", "").strip()


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
    if not src_path.exists() or not src_path.is_dir():
        raise RuntimeError(f"Invalid local repo path: {src_path}")

    dest = dest_root / src_path.name
    shutil.copytree(src_path, dest)
    return dest


def tool_installed(name: str) -> bool:
    return shutil.which(name) is not None


def inventory_repo(repo_path: Path) -> dict:
    return {
        "repo_path": str(repo_path),
        "python_file_count": len(list(repo_path.rglob("*.py"))),
        "terraform_file_count": len(list(repo_path.rglob("*.tf"))),
        "has_requirements_txt": (repo_path / "requirements.txt").exists(),
        "has_pyproject_toml": (repo_path / "pyproject.toml").exists(),
        "has_security_manifest": (repo_path / "security_manifest.json").exists(),
    }


def load_security_manifest(repo_path: Path) -> dict:
    manifest_path = repo_path / "security_manifest.json"
    if not manifest_path.exists():
        return {"approved_scripts": []}
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return {"approved_scripts": []}


def run_approved_scripts(repo_path: Path) -> list[dict]:
    manifest = load_security_manifest(repo_path)
    results = []

    for entry in manifest.get("approved_scripts", []):
        rel_path = entry.get("path", "")
        args = entry.get("args", [])
        script_path = (repo_path / rel_path).resolve()

        # Prevent escaping the repo root
        if repo_path.resolve() not in script_path.parents and script_path != repo_path.resolve():
            results.append({
                "tool": "custom_script",
                "status": "skipped",
                "script": rel_path,
                "reason": "Script path escapes repo root",
            })
            continue

        if not script_path.exists():
            results.append({
                "tool": "custom_script",
                "status": "skipped",
                "script": rel_path,
                "reason": "Script not found",
            })
            continue

        code, out, err = run_command(["python3", str(script_path), *args], cwd=repo_path)
        results.append({
            "tool": "custom_script",
            "script": rel_path,
            "status": "ok" if code == 0 else "error",
            "exit_code": code,
            "stdout": out,
            "stderr": err,
        })

    return results


def run_bandit(repo_path: Path) -> dict:
    if not tool_installed("bandit"):
        return {"tool": "bandit", "status": "skipped", "reason": "bandit not installed"}
    code, out, err = run_command(["bandit", "-r", str(repo_path), "-f", "json"])
    return {"tool": "bandit", "status": "ok" if code in (0, 1) else "error", "exit_code": code, "raw": out or err}


def run_semgrep(repo_path: Path, config: str = "auto") -> dict:
    if not tool_installed("semgrep"):
        return {"tool": "semgrep", "status": "skipped", "reason": "semgrep not installed"}
    code, out, err = run_command(["semgrep", "scan", "--config", config, "--json", str(repo_path)])
    return {"tool": "semgrep", "status": "ok" if code in (0, 1) else "error", "exit_code": code, "raw": out or err}


def run_checkov_tf(repo_path: Path) -> dict:
    if not tool_installed("checkov"):
        return {"tool": "checkov_tf", "status": "skipped", "reason": "checkov not installed"}
    code, out, err = run_command(["checkov", "-d", str(repo_path), "--framework", "terraform", "--output", "json"])
    return {"tool": "checkov_tf", "status": "ok" if code in (0, 1) else "error", "exit_code": code, "raw": out or err}


def run_pip_audit(repo_path: Path) -> dict:
    if not tool_installed("pip-audit"):
        return {"tool": "pip-audit", "status": "skipped", "reason": "pip-audit not installed"}
    req = repo_path / "requirements.txt"
    if not req.exists():
        return {"tool": "pip-audit", "status": "skipped", "reason": "requirements.txt not found"}
    code, out, err = run_command(["pip-audit", "-r", str(req), "--format", "json"], cwd=repo_path)
    return {"tool": "pip-audit", "status": "ok" if code in (0, 1) else "error", "exit_code": code, "raw": out or err}


def find_terraform_dir(repo_path: Path) -> Path | None:
    tf_files = list(repo_path.rglob("*.tf"))
    if not tf_files:
        return None
    # Use the parent of the first .tf file for this teaching version
    return tf_files[0].parent


def run_terraform_plan_security(terraform_dir: Path) -> list[dict]:
    results = []

    if not tool_installed("terraform"):
        return [{"tool": "terraform_plan_security", "status": "skipped", "reason": "terraform not installed"}]

    # fmt
    code, out, err = run_command(["terraform", "fmt"], cwd=terraform_dir)
    results.append({"tool": "terraform_fmt", "status": "ok" if code == 0 else "error", "exit_code": code, "stdout": out, "stderr": err})

    # init
    code, out, err = run_command(["terraform", "init", "-backend=false"], cwd=terraform_dir)
    results.append({"tool": "terraform_init", "status": "ok" if code == 0 else "error", "exit_code": code, "stdout": out, "stderr": err})
    if code != 0:
        return results

    # validate
    code, out, err = run_command(["terraform", "validate"], cwd=terraform_dir)
    results.append({"tool": "terraform_validate", "status": "ok" if code == 0 else "error", "exit_code": code, "stdout": out, "stderr": err})
    if code != 0:
        return results

    # plan
    code, out, err = run_command(["terraform", "plan", "-out=tfplan", "-no-color"], cwd=terraform_dir)
    results.append({"tool": "terraform_plan", "status": "ok" if code == 0 else "error", "exit_code": code, "stdout": out, "stderr": err})
    if code != 0:
        return results

    # show -json
    code, out, err = run_command(["terraform", "show", "-json", "tfplan"], cwd=terraform_dir)
    results.append({"tool": "terraform_show_json", "status": "ok" if code == 0 else "error", "exit_code": code, "stdout": out, "stderr": err})
    if code != 0:
        return results

    tfplan_json_path = terraform_dir / "tfplan.json"
    tfplan_json_path.write_text(out, encoding="utf-8")

    # checkov on plan json
    if tool_installed("checkov"):
        code, out, err = run_command(["checkov", "-f", str(tfplan_json_path), "--framework", "terraform_plan", "--output", "json"], cwd=terraform_dir)
        results.append({"tool": "checkov_plan", "status": "ok" if code in (0, 1) else "error", "exit_code": code, "raw": out or err})
    else:
        results.append({"tool": "checkov_plan", "status": "skipped", "reason": "checkov not installed"})

    return results


def build_triage_prompt(repo_inventory: dict, tool_results: list[dict]) -> str:
    return f"""
You are a Security Triage Agent for an internal AI DevSecOps pipeline.

Your job:
- Review all scanner and script results
- Highlight the most important findings
- Compare static Terraform findings with terraform plan findings when present
- Note likely false positives or low-priority noise
- Recommend PASS, WARN, or FAIL

Repository inventory:
{json.dumps(repo_inventory, indent=2)}

Tool results:
{json.dumps(tool_results, indent=2)[:30000]}

Return exactly this format:

TRIAGE_SUMMARY:
<short summary>

TOP_FINDINGS:
- item
- item

STATIC_VS_PLAN_NOTES:
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
    print("\\n=== AI DevSecOps Pipeline ===\\n")
    print("Only scan repositories you own or are explicitly authorized to assess.\\n")

    raw_sources = input("Enter local repo paths or authorized Git repo URLs, separated by commas:\\n> ").strip()
    if not raw_sources:
        print("No repos provided.")
        return

    semgrep_config = input("Semgrep config (default: auto): ").strip() or "auto"
    sources = [s.strip() for s in raw_sources.split(",") if s.strip()]

    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    WORKDIR.mkdir(parents=True, exist_ok=True)

    for source in sources:
        print(f"\\n{'=' * 20} SOURCE: {source} {'=' * 20}")

        try:
            repo_path = clone_or_copy_repo(source, WORKDIR / "repos")
        except Exception as e:
            print(f"[ERROR] {e}")
            continue

        inventory = inventory_repo(repo_path)
        print(json.dumps(inventory, indent=2))

        all_results = []

        if inventory["python_file_count"] > 0:
            all_results.append(run_bandit(repo_path))
            all_results.append(run_semgrep(repo_path, config=semgrep_config))

        if inventory["terraform_file_count"] > 0:
            all_results.append(run_checkov_tf(repo_path))

            terraform_dir = find_terraform_dir(repo_path)
            if terraform_dir:
                all_results.extend(run_terraform_plan_security(terraform_dir))

        if inventory["has_requirements_txt"]:
            all_results.append(run_pip_audit(repo_path))

        all_results.extend(run_approved_scripts(repo_path))

        save_text(WORKDIR / f"{repo_path.name}_results.json", json.dumps(all_results, indent=2))

        triage_prompt = build_triage_prompt(inventory, all_results)
        triage = call_ollama(TRIAGE_MODEL, triage_prompt)
        print("\\n--- TRIAGE AGENT ---\\n")
        print(triage)
        save_text(WORKDIR / f"{repo_path.name}_triage.txt", triage)

    print(f"\\nDone. Reports saved under: {WORKDIR}\\n")


if __name__ == "__main__":
    main()
