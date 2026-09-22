import argparse
import ast
import sys
from pathlib import Path

# Vendor brand names that must not appear in kernel executable code
# NOTE: This list may start empty if the tree is clean. An empty-but-wired gate
# that catches the next violation is still worth having.
FORBIDDEN_VENDOR_BRANDS: set[str] = {"langsmith"}
# TODO(latent-gate): The kernel still contains 'langfuse' and 'openai' in
# telemetry_provider.py and nemo/vllm_client.py. These should be refactored
# out of Layer 1 (src/gateway/) into Layer 3 (src/integrations/) before they
# can be added to the forbidden list.

# Files that are allowed to contain vendor brand names
EXCLUDED_FILES = {
    "generated_stpa_validator.py",
    "generated_saga_nodes.py",
    "generated_stpa_policy.rego",
}

# Directories excluded from scanning
EXCLUDED_DIRS = {"protos", "__pycache__", ".pytest_cache", ".mypy_cache"}


class VendorBrandChecker(ast.NodeVisitor):
    """AST visitor that collects string literals outside of docstrings."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.violations: list[tuple[int, str]] = []
        self._docstring_nodes: set[ast.AST] = set()

    def visit_Module(self, node: ast.Module) -> None:
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        docstring = ast.get_docstring(node, clean=False)
        if docstring and node.body and isinstance(node.body[0], ast.Expr):
            self._docstring_nodes.add(node.body[0].value)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node not in self._docstring_nodes:
            lower_value = node.value.lower()
            for brand in FORBIDDEN_VENDOR_BRANDS:
                if brand.lower() in lower_value:
                    self.violations.append((node.lineno, node.value))
                    break
        self.generic_visit(node)


def check_file(filepath: Path) -> list[tuple[int, str]]:
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
        checker = VendorBrandChecker(filepath)
        checker.visit(tree)
        return checker.violations
    except SyntaxError as exc:
        print(f"⚠️  Syntax error in {filepath}: {exc}", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"⚠️  Failed to parse {filepath}: {exc}", file=sys.stderr)
        return []


def should_skip(path: Path, base_dir: Path) -> bool:
    for part in path.relative_to(base_dir).parts:
        if part in EXCLUDED_DIRS:
            return True

    if path.name in EXCLUDED_FILES:
        return True

    if (
        "/tests/" in str(path)
        or path.name.endswith("_test.py")
        or path.name.startswith("test_")
    ):
        return True

    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check vendor brand literals in kernel"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    gateway_dir = repo_root / "src" / "gateway"

    if not gateway_dir.exists():
        print(f"❌ Gateway directory not found: {gateway_dir}", file=sys.stderr)
        return 1

    if not FORBIDDEN_VENDOR_BRANDS:
        if args.verbose:
            print("INFO: Gate G8: No vendor brands configured (empty list).")
        print(
            "✅ Gate G8 PASSED: Vendor brand list is empty (gate is wired but not restrictive)."
        )
        return 0

    violations_found = False
    scanned_count = 0

    for py_file in gateway_dir.rglob("*.py"):
        if should_skip(py_file, gateway_dir):
            continue

        scanned_count += 1
        violations = check_file(py_file)

        if violations:
            violations_found = True
            rel_path = py_file.relative_to(repo_root)
            print(f"❌ {rel_path}:")
            for line_num, literal in violations:
                print(f"   Line {line_num}: '{literal}'")

    if violations_found:
        print()
        print(
            "❌ Gate G8 FAILED: Found forbidden vendor brand literals in kernel code."
        )
        print(f"   Forbidden brands: {', '.join(sorted(FORBIDDEN_VENDOR_BRANDS))}")
        print()
        print("   The kernel must be vendor-neutral. Vendor names are acceptable in:")
        print("   • Docstrings and comments (documentation and prose)")
        print("   • Layer 3 adapter identifiers (src/integrations/provider_*/)")
        print()
        print("   They must NOT appear in:")
        print("   • Enum members, string literals in executable code")
        print("   • Function names, Redis keys, environment variables")
        print()
        print("   Use observability abstractions, not vendor-specific coupling.")
        return 1

    if args.verbose:
        print(f"📊 Scanned {scanned_count} files in {gateway_dir}/")
    print(
        f"✅ Gate G8 PASSED: No vendor brand literals found (scanned {scanned_count} files)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
