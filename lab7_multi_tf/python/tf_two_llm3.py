#Thanks Guy

import json
import urllib.request
import urllib.error


OLLAMA_URL = "http://localhost:11434/api/generate"

BUILDER_MODEL = "llama3.2"
REVIEWER_MODEL = "deepseek-r1"


def call_ollama(model: str, prompt: str) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=1200) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body)
            return parsed.get("response", "").strip()
    except urllib.error.URLError as e:
        return f"[ERROR] Could not reach Ollama: {e}"
    except Exception as e:
        return f"[ERROR] Unexpected error: {e}"


def build_builder_prompt() -> str:
    return """
You are a Terraform Builder.

Your task:
Generate Terraform code for AWS that creates:

- 1 VPC with CIDR block 10.0.0.0/16
- 2 public subnets in different availability zones
- 1 internet gateway
- 1 public route table
- route table associations for both public subnets
- consistent Name tags on all resources

Requirements:
- Output Terraform code only
- Use AWS provider
- Use clear resource names
- Use valid Terraform HCL
- Keep the solution beginner-friendly and readable
- Include variables only if truly needed
- Do not include explanations outside the code
""".strip()


def build_reviewer_prompt(terraform_code: str) -> str:
    return f"""
You are a strict Terraform Reviewer.

Review the Terraform code below.

Your job:
- Identify strengths
- Identify problems
- Identify missing resources or best practices
- Identify security or maintainability concerns
- Suggest improvements
- If possible, provide an improved version

Return your review in exactly this format:

REVIEW_SUMMARY:
<short summary>

STRENGTHS:
- item
- item

ISSUES_FOUND:
- item
- item

RECOMMENDED_FIXES:
- item
- item

IMPROVED_TERRAFORM:
```hcl
{terraform_code}""".strip()

def extract_improved_terraform(review_text: str) -> str:
    """Extract the HCL block from the reviewer output."""
    marker = "IMPROVED_TERRAFORM:"
    marker_index = review_text.find(marker)

    if marker_index == -1:
        return ""
      
    code_start = review_text.find("```hcl", marker_index)
    if code_start == -1:
        return ""
      
    code_start += len("```hcl")
    code_end = review_text.find("```", code_start)
    if code_end == -1:
        return ""
      
    return review_text[code_start:code_end].strip()

def save_file(filename: str, content: str) -> None:
    """Save text to a file."""
    with open(filename, "w", encoding="utf-8") as file:
        file.write(content)

def main():
    print("\n=== Two-LLM Terraform Demo ===\n")
    # Step 1: Builder generates Terraform code.

    builder_prompt = build_builder_prompt()
    print(">>> Builder is generating Terraform code...")
    terraform_code = call_ollama(BUILDER_MODEL, builder_prompt)
    print("\n--- Generated Terraform Code ---\n")
    print(terraform_code)
    save_file("generated.tf", terraform_code)
    # Step 2: Reviewer reviews the generated code.
    reviewer_prompt = build_reviewer_prompt(terraform_code)
    print("\n>>> Reviewer is reviewing the generated code...")
    review = call_ollama(REVIEWER_MODEL, reviewer_prompt)
    print("\n--- Review Output ---\n")
    print(review)
    save_file("review.txt", review)
    # Step 3: Extract improved Terraform from the review.
    improved_terraform = extract_improved_terraform(review)
    if improved_terraform:
        print("\n--- Improved Terraform Code ---\n")
        print(improved_terraform)
        save_file("improved.tf", improved_terraform)
    else:
        print("\n[INFO] No improved Terraform code found in the review.")


if __name__ == "__main__":
    main()
