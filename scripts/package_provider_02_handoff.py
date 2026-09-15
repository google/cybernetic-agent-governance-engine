# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Package Provider_02 Native Schema Handoff Archive

Validates, hashes, manifests, and bundles all Phase 1 and Phase 2 assets
into a clean handoff archive for NexArt.

Usage:
    python scripts/package_provider_02_handoff.py
    uv run python scripts/package_provider_02_handoff.py
"""

import hashlib
import json
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import jsonschema
    from jsonschema import Draft7Validator, RefResolver
except ImportError:
    print("ERROR: jsonschema package not found. Install with: pip install jsonschema")
    sys.exit(1)


# --- Configuration ---
PROJECT_ROOT = Path(__file__).parent.parent
SCHEMA_DIR = PROJECT_ROOT / "schemas" / "provider_02"
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "provider_02_native"
ARCHITECTURE_SPEC = (
    PROJECT_ROOT / "docs" / "architecture" / "provider_02_native_schema_spec.md"
)
DIST_DIR = PROJECT_ROOT / "dist"
ARCHIVE_BASENAME = "provider_02_native_schema_v1"

# Files to include in the package
SOURCE_ASSETS = [
    SCHEMA_DIR,
    ARCHITECTURE_SPEC,
    FIXTURES_DIR,
]

SCHEMA_FILE = SCHEMA_DIR / "attestation_bundle.schema.json"


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def validate_fixtures(schema_path: Path, fixtures_dir: Path) -> bool:
    """
    Validate all JSON fixtures against the attestation bundle schema.

    Returns:
        True if all fixtures pass validation, False otherwise.
    """
    print("=" * 80)
    print("Phase 1: Pre-flight Schema Validation")
    print("=" * 80)

    if not schema_path.exists():
        print(f"ERROR: Schema file not found: {schema_path}")
        return False

    if not fixtures_dir.exists():
        print(f"ERROR: Fixtures directory not found: {fixtures_dir}")
        return False

    # Load main schema
    try:
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load schema from {schema_path}: {e}")
        return False

    # Load all schemas in the schema directory for reference resolution
    schema_store = {}
    schema_dir = schema_path.parent

    for schema_file in schema_dir.glob("*.schema.json"):
        try:
            with open(schema_file, encoding="utf-8") as f:
                sub_schema = json.load(f)
                # Map URN $id to schema content
                if "$id" in sub_schema:
                    schema_store[sub_schema["$id"]] = sub_schema
        except Exception as e:
            print(f"WARNING: Failed to load schema {schema_file}: {e}")

    # Create validator with custom resolver for URN references
    try:
        resolver = RefResolver.from_schema(schema, store=schema_store)
        validator = Draft7Validator(schema, resolver=resolver)
    except Exception as e:
        print(f"ERROR: Invalid schema: {e}")
        return False

    # Find all JSON fixture files
    fixture_files = list(fixtures_dir.glob("*.json"))

    if not fixture_files:
        print(f"WARNING: No JSON fixtures found in {fixtures_dir}")
        return True

    print(f"Validating {len(fixture_files)} fixture(s) against schema...\n")

    all_valid = True
    for fixture_file in sorted(fixture_files):
        try:
            with open(fixture_file, encoding="utf-8") as f:
                fixture_data = json.load(f)

            # Validate
            errors = list(validator.iter_errors(fixture_data))

            if errors:
                print(f"✗ {fixture_file.name}: FAILED")
                for error in errors:
                    print(f"  - {error.message}")
                    if error.path:
                        print(f"    Path: {' -> '.join(str(p) for p in error.path)}")
                all_valid = False
            else:
                print(f"✓ {fixture_file.name}: PASSED")

        except json.JSONDecodeError as e:
            print(f"✗ {fixture_file.name}: INVALID JSON - {e}")
            all_valid = False
        except Exception as e:
            print(f"✗ {fixture_file.name}: ERROR - {e}")
            all_valid = False

    print()
    if all_valid:
        print("✓ All fixtures passed validation\n")
    else:
        print("✗ One or more fixtures failed validation\n")

    return all_valid


def collect_files(source_assets: list[Path]) -> list[Path]:
    """Recursively collect all files from source asset paths."""
    collected_files = []

    for asset_path in source_assets:
        if not asset_path.exists():
            print(f"WARNING: Asset not found, skipping: {asset_path}")
            continue

        if asset_path.is_file():
            collected_files.append(asset_path)
        elif asset_path.is_dir():
            # Recursively collect all files in directory
            for file_path in sorted(asset_path.rglob("*")):
                if file_path.is_file():
                    collected_files.append(file_path)

    return collected_files


def generate_manifest(files: list[Path], project_root: Path) -> dict[str, Any]:
    """Generate manifest with file metadata and SHA-256 hashes."""
    print("=" * 80)
    print("Phase 2: SHA-256 Digest Computation")
    print("=" * 80)

    file_entries = []

    for file_path in sorted(files):
        # Compute relative path from project root
        try:
            rel_path = file_path.relative_to(project_root)
        except ValueError:
            # File is outside project root, use absolute path
            rel_path = file_path

        file_size = file_path.stat().st_size
        file_hash = compute_sha256(file_path)

        file_entries.append(
            {
                "path": str(rel_path),
                "sha256": file_hash,
                "bytes": file_size,
            }
        )

        print(f"  {rel_path}")
        print(f"    SHA-256: {file_hash}")
        print(f"    Size: {file_size:,} bytes")

    print()

    manifest = {
        "urn": "urn:cage:governance:v1",
        "spec_version": "1.0.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": file_entries,
        "validation_status": "PASSED",
    }

    return manifest


def create_archives(
    files: list[Path],
    manifest: dict[str, Any],
    project_root: Path,
    dist_dir: Path,
    basename: str,
) -> tuple[Path, Path]:
    """Create tar.gz and zip archives with manifest."""
    print("=" * 80)
    print("Phase 3: Archive Assembly")
    print("=" * 80)

    # Create dist directory if it doesn't exist
    dist_dir.mkdir(parents=True, exist_ok=True)

    tar_path = dist_dir / f"{basename}.tar.gz"
    zip_path = dist_dir / f"{basename}.zip"

    # Create manifest JSON content
    manifest_content = json.dumps(manifest, indent=2, ensure_ascii=False)

    # Create tar.gz archive
    print(f"Creating {tar_path}...")
    with tarfile.open(tar_path, "w:gz") as tar:
        # Add manifest
        from io import BytesIO

        manifest_bytes = manifest_content.encode("utf-8")
        manifest_info = tarfile.TarInfo(name="MANIFEST.json")
        manifest_info.size = len(manifest_bytes)
        tar.addfile(manifest_info, BytesIO(manifest_bytes))

        # Add all files
        for file_path in sorted(files):
            try:
                arcname = str(file_path.relative_to(project_root))
            except ValueError:
                arcname = file_path.name
            tar.add(file_path, arcname=arcname)

    # Create zip archive
    print(f"Creating {zip_path}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add manifest
        zf.writestr("MANIFEST.json", manifest_content)

        # Add all files
        for file_path in sorted(files):
            try:
                arcname = str(file_path.relative_to(project_root))
            except ValueError:
                arcname = file_path.name
            zf.write(file_path, arcname=arcname)

    print()
    return tar_path, zip_path


def print_summary(
    files: list[Path], manifest: dict[str, Any], tar_path: Path, zip_path: Path
) -> None:
    """Print clean summary table."""
    print("=" * 80)
    print("Package Summary")
    print("=" * 80)
    print()

    print(f"Total Files: {len(files)}")
    print(f"Validation Status: {manifest['validation_status']}")
    print(f"Created: {manifest['created_at_utc']}")
    print()

    print("Files Included:")
    print("-" * 80)
    print(f"{'Path':<50} {'Size':>12} {'SHA-256':<64}")
    print("-" * 80)

    for entry in manifest["files"]:
        path = entry["path"]
        size = entry["bytes"]
        sha = entry["sha256"]

        # Truncate path if too long
        if len(path) > 48:
            path = "..." + path[-45:]

        print(f"{path:<50} {size:>12,} {sha}")

    print("-" * 80)
    print()

    print("Archives Created:")
    print(f"  ✓ {tar_path} ({tar_path.stat().st_size:,} bytes)")
    print(f"  ✓ {zip_path} ({zip_path.stat().st_size:,} bytes)")
    print()

    print("=" * 80)
    print("✓ Packaging Complete")
    print("=" * 80)


def main() -> int:
    """Main packaging workflow."""
    print()
    print("╔" + "=" * 78 + "╗")
    print(
        "║" + " " * 15 + "Provider_02 Native Schema Handoff Packager" + " " * 21 + "║"
    )
    print("╚" + "=" * 78 + "╝")
    print()

    # Phase 1: Validate fixtures
    if not validate_fixtures(SCHEMA_FILE, FIXTURES_DIR):
        print("ERROR: Fixture validation failed. Aborting packaging.")
        return 1

    # Collect all files to package
    files = collect_files(SOURCE_ASSETS)

    if not files:
        print("ERROR: No files found to package.")
        return 1

    # Phase 2: Generate manifest with SHA-256 hashes
    manifest = generate_manifest(files, PROJECT_ROOT)

    # Phase 3: Create archives
    tar_path, zip_path = create_archives(
        files, manifest, PROJECT_ROOT, DIST_DIR, ARCHIVE_BASENAME
    )

    # Print summary
    print_summary(files, manifest, tar_path, zip_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
