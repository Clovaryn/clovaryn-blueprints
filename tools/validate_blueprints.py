from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import stat
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jinja2 import FileSystemLoader, StrictUndefined
from jinja2.sandbox import SandboxedEnvironment
from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGES_ROOT = REPO_ROOT / "packages" / "official"

KEBAB_CASE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
SUPPORTED_TEMPLATE_LANGUAGES = {"terraform"}
SUPPORTED_IAC_TARGETS = {"terraform", "opentofu"}

MAX_PACKAGE_BYTES = 5 * 1024 * 1024
MAX_FILE_COUNT = 500
MAX_FILE_BYTES = 512 * 1024
MAX_TEMPLATE_BYTES = 256 * 1024

ALLOWED_PACKAGE_SUFFIXES = {".toml", ".json", ".yaml", ".yml", ".j2", ".md"}
ALLOWED_TEMPLATE_NAMES = {"terraform.tfvars.j2"}
FORBIDDEN_SUFFIXES = {
    ".tfstate",
    ".tfplan",
    ".pem",
    ".key",
    ".p12",
    ".log",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".py",
}
FORBIDDEN_EXACT_NAMES = {
    "terraform.tfvars",
    "tfplan",
    ".env",
    "crash.log",
    "override.tf",
    "override.tf.json",
}
FORBIDDEN_NAME_PATTERNS = (
    re.compile(r"^\.env\..+"),
    re.compile(r"^backend.*\.hcl$"),
    re.compile(r".*\.tfstate\.backup$"),
    re.compile(r".*\.auto\.tfvars$"),
    re.compile(r".*\.tfvars\.json$"),
    re.compile(r"^crash\..*\.log$"),
    re.compile(r".*_override\.tf$"),
    re.compile(r".*_override\.tf\.json$"),
    re.compile(r".*credentials?.*\.json$"),
    re.compile(r".*service[-_]?account.*\.json$"),
    re.compile(r".*gcp-key.*\.json$"),
    re.compile(r".*google-application-credentials.*\.json$"),
)

IGNORED_REPOSITORY_PARTS = {".clovaryn", ".pytest_cache", "__pycache__", "generated", "node_modules"}


class ValidationError(RuntimeError):
    pass


def _rel(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _hcl(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return json.dumps(value, sort_keys=True)


def _is_forbidden_path(path: Path) -> bool:
    name = path.name
    lower_name = name.lower()
    if lower_name in FORBIDDEN_EXACT_NAMES:
        return True
    if path.suffix.lower() == ".tf" and not lower_name.endswith(".tf.j2"):
        return True
    if any(lower_name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        return True
    if any(pattern.fullmatch(lower_name) for pattern in FORBIDDEN_NAME_PATTERNS):
        return True
    return False


def _is_allowed_template_source(path: Path) -> bool:
    lower_name = path.name.lower()
    return lower_name.endswith(".tf.j2") or lower_name in ALLOWED_TEMPLATE_NAMES


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _discover_package_roots() -> list[Path]:
    if not PACKAGES_ROOT.exists():
        return []
    roots: list[Path] = []
    for package_name_dir in sorted(path for path in PACKAGES_ROOT.iterdir() if path.is_dir()):
        for version_dir in sorted(path for path in package_name_dir.iterdir() if path.is_dir()):
            if (version_dir / "clovaryn.package.toml").exists():
                roots.append(version_dir)
    return roots


def _validate_repository_file_safety() -> None:
    allowed_hidden_parts = {".github"}
    allowed_hidden_files = {".gitignore"}
    for path in sorted(REPO_ROOT.rglob("*")):
        rel_parts = path.relative_to(REPO_ROOT).parts
        if not rel_parts or rel_parts[0] == ".git":
            continue
        if any(part in IGNORED_REPOSITORY_PARTS for part in rel_parts):
            continue
        if path.is_symlink():
            raise ValidationError(f"Symlinks are not allowed: {_rel(path)}")
        for part in rel_parts:
            if part.startswith(".") and part not in allowed_hidden_parts and part not in allowed_hidden_files:
                raise ValidationError(f"Unexpected hidden path is not allowed: {_rel(path)}")
        if path.is_dir():
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if _is_forbidden_path(path) and not rel.startswith("tools/"):
            raise ValidationError(f"Forbidden file is not allowed: {_rel(path)}")
        if _looks_binary(path.read_bytes()):
            raise ValidationError(f"Binary or non-UTF-8 file is not allowed: {_rel(path)}")


def _validate_package_file_safety(package_root: Path) -> list[Path]:
    files: list[Path] = []
    total_bytes = 0
    root_resolved = package_root.resolve()
    for path in sorted(package_root.rglob("*")):
        if path.is_symlink():
            raise ValidationError(f"Symlinks are not allowed: {_rel(path)}")
        if path.resolve().is_relative_to(root_resolved) is False:
            raise ValidationError(f"Path traversal is not allowed: {_rel(path)}")
        if any(part.startswith(".") for part in path.relative_to(package_root).parts):
            raise ValidationError(f"Unexpected hidden path is not allowed: {_rel(path)}")
        if path.is_dir():
            continue
        files.append(path)
        data = path.read_bytes()
        total_bytes += len(data)
        if len(files) > MAX_FILE_COUNT:
            raise ValidationError(f"Package has too many files: {_rel(package_root)}")
        if total_bytes > MAX_PACKAGE_BYTES:
            raise ValidationError(f"Package exceeds max size: {_rel(package_root)}")
        if len(data) > MAX_FILE_BYTES:
            raise ValidationError(f"File exceeds max size: {_rel(path)}")
        if path.suffix == ".j2" and len(data) > MAX_TEMPLATE_BYTES:
            raise ValidationError(f"Template exceeds max size: {_rel(path)}")
        if path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise ValidationError(f"Executable files are not allowed: {_rel(path)}")
        if _is_forbidden_path(path):
            raise ValidationError(f"Forbidden file is not allowed: {_rel(path)}")
        if path.suffix.lower() not in ALLOWED_PACKAGE_SUFFIXES:
            raise ValidationError(f"Unexpected package file type is not allowed: {_rel(path)}")
        if path.suffix.lower() == ".j2" and not _is_allowed_template_source(path):
            raise ValidationError(f"Unexpected template type is not allowed: {_rel(path)}")
        if _looks_binary(data):
            raise ValidationError(f"Binary or non-UTF-8 file is not allowed: {_rel(path)}")
    return files


def _validate_variant_target_metadata(
    package_root: Path,
    variant: dict[str, Any],
    yaml_variant: dict[str, Any] | None = None,
) -> None:
    variant_id = variant.get("id", "<unknown>")
    template_dir = variant.get("template_dir")
    template_language = variant.get("template_language")
    supported_iac_targets = variant.get("supported_iac_targets")

    if not isinstance(template_dir, str) or not template_dir:
        raise ValidationError(f"Variant template_dir must be a non-empty string: {_rel(package_root)}:{variant_id}")
    if "opentofu" in (supported_iac_targets if isinstance(supported_iac_targets, list) else []):
        if template_language != "terraform":
            raise ValidationError(
                f"Variant declaring OpenTofu support must use template_language = terraform: {_rel(package_root)}:{variant_id}"
            )
    if template_language not in SUPPORTED_TEMPLATE_LANGUAGES:
        raise ValidationError(
            f"Variant template_language must be one of {sorted(SUPPORTED_TEMPLATE_LANGUAGES)}: "
            f"{_rel(package_root)}:{variant_id}"
        )
    if template_language == "terraform" and template_dir != "templates/terraform":
        raise ValidationError(f"Terraform-language variants must use templates/terraform: {_rel(package_root)}:{variant_id}")
    if not isinstance(supported_iac_targets, list) or not supported_iac_targets:
        raise ValidationError(f"Variant supported_iac_targets must be a non-empty list: {_rel(package_root)}:{variant_id}")
    invalid_targets = sorted(
        str(target) for target in supported_iac_targets if not isinstance(target, str) or target not in SUPPORTED_IAC_TARGETS
    )
    if invalid_targets:
        raise ValidationError(
            f"Variant supported_iac_targets must use canonical values {sorted(SUPPORTED_IAC_TARGETS)}: "
            f"{_rel(package_root)}:{variant_id}"
        )
    if len(set(supported_iac_targets)) != len(supported_iac_targets):
        raise ValidationError(f"Variant supported_iac_targets contains duplicates: {_rel(package_root)}:{variant_id}")

    if yaml_variant is not None:
        for key in ("template_language", "supported_iac_targets"):
            if yaml_variant.get(key) != variant.get(key):
                raise ValidationError(f"Variant YAML must match manifest {key}: {_rel(package_root)}:{variant_id}")


def _validate_package_metadata(package_root: Path) -> dict[str, Any]:
    package_name = package_root.parent.name
    version = package_root.name
    if not KEBAB_CASE_RE.fullmatch(package_name):
        raise ValidationError(f"Package folder must be lowercase kebab-case: {_rel(package_root.parent)}")
    if not SEMVER_RE.fullmatch(version):
        raise ValidationError(f"Package version folder must be exact semver: {_rel(package_root)}")

    manifest = _load_toml(package_root / "clovaryn.package.toml")
    package = manifest.get("package", {})
    if package.get("name") != package_name:
        raise ValidationError(f"Manifest package.name must match folder name: {_rel(package_root)}")
    if package.get("version") != version:
        raise ValidationError(f"Manifest package.version must match version folder: {_rel(package_root)}")

    families = manifest.get("families", [])
    variants = manifest.get("variants", [])
    rules = manifest.get("rules", [])
    bindings = manifest.get("bindings", {})
    family_ids = {family.get("id") for family in families}
    variant_ids = {variant.get("id") for variant in variants}
    rule_ids = {rule.get("id") for rule in rules}

    if not family_ids or not variant_ids:
        raise ValidationError(f"Package must define at least one family and variant: {_rel(package_root)}")
    if bindings.get("default_family_id") not in family_ids:
        raise ValidationError(f"default_family_id does not match a manifest family: {_rel(package_root)}")
    if bindings.get("default_variant_id") not in variant_ids:
        raise ValidationError(f"default_variant_id does not match a manifest variant: {_rel(package_root)}")

    yaml_family_ids = {
        loaded.get("id")
        for loaded in (_load_yaml(path) for path in sorted((package_root / "families").glob("*.yaml")))
        if isinstance(loaded, dict)
    }
    yaml_variants_by_id: dict[str, dict[str, Any]] = {}
    for path in sorted((package_root / "variants").glob("*.yaml")):
        loaded = _load_yaml(path)
        if not isinstance(loaded, dict):
            raise ValidationError(f"Variant YAML must be an object: {_rel(path)}")
        if loaded.get("id"):
            yaml_variants_by_id[loaded["id"]] = loaded
    yaml_variant_ids = set(yaml_variants_by_id)
    yaml_rule_ids: set[str] = set()
    for path in sorted((package_root / "rules").glob("*.yaml")):
        loaded = _load_yaml(path)
        if not isinstance(loaded, dict):
            raise ValidationError(f"Rule YAML must be an object: {_rel(path)}")
        for rule in loaded.get("rules", []):
            if isinstance(rule, dict) and rule.get("id"):
                yaml_rule_ids.add(rule["id"])

    if not family_ids.issubset(yaml_family_ids):
        raise ValidationError(f"Family YAML files must include all manifest families: {_rel(package_root)}")
    if not variant_ids.issubset(yaml_variant_ids):
        raise ValidationError(f"Variant YAML files must include all manifest variants: {_rel(package_root)}")
    if not rule_ids.issubset(yaml_rule_ids):
        raise ValidationError(f"Rule YAML files must include all manifest rules: {_rel(package_root)}")

    for variant in variants:
        template_dir = package_root / variant.get("template_dir", "")
        if not template_dir.exists() or not template_dir.is_dir():
            raise ValidationError(f"Variant template_dir does not exist: {_rel(package_root)}")
        _validate_variant_target_metadata(package_root, variant, yaml_variants_by_id.get(variant.get("id")))

    return manifest


def _validate_schema_files(package_root: Path) -> dict[str, Any]:
    schema_path = package_root / "schemas" / "intent.schema.json"
    if not schema_path.exists():
        raise ValidationError(f"Missing intent schema: {_rel(schema_path)}")
    schema = _load_json(schema_path)
    Draft202012Validator.check_schema(schema)
    return schema


def _load_intent(path: Path) -> dict[str, Any]:
    return _load_toml(path)


def _validate_private_ecs_intent(intent: dict[str, Any], path: Path) -> list[str]:
    issues: list[str] = []
    network = intent.get("inputs", {}).get("network", {})
    if network.get("exposure") != "internal_only":
        issues.append("network.exposure must be internal_only")
    if network.get("public_subnet_ids"):
        issues.append("public_subnet_ids must be empty")
    if not network.get("private_subnet_ids"):
        issues.append("private_subnet_ids must be non-empty")
    for cidr in network.get("allowed_cidr_blocks", []):
        if cidr in PUBLIC_CIDRS:
            issues.append(f"public CIDR is not allowed for internal-only ECS: {cidr}")
    return [f"{_rel(path)}: {issue}" for issue in issues]


def _validate_private_s3_intent(intent: dict[str, Any], path: Path) -> list[str]:
    issues: list[str] = []
    storage = intent.get("inputs", {}).get("storage", {})
    if storage.get("block_public_access") is not True:
        issues.append("storage.block_public_access must be true")
    if storage.get("encryption_enabled") is not True:
        issues.append("storage.encryption_enabled must be true")
    return [f"{_rel(path)}: {issue}" for issue in issues]


def _package_declares_ecs_backend(manifest: dict[str, Any]) -> bool:
    package = manifest.get("package", {})
    if package.get("name") == "aws-private-ecs-backend":
        return True
    family_ids = {family.get("id", "") for family in manifest.get("families", [])}
    return any("ecs" in family_id and "backend" in family_id for family_id in family_ids)


def _package_declares_s3_private_bucket(manifest: dict[str, Any]) -> bool:
    package = manifest.get("package", {})
    if package.get("name") == "aws-s3-private-bucket":
        return True
    family_ids = {family.get("id", "") for family in manifest.get("families", [])}
    return any("s3" in family_id and "bucket" in family_id for family_id in family_ids)


def _validate_package_intent(intent: dict[str, Any], path: Path, manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if _package_declares_ecs_backend(manifest):
        issues.extend(_validate_private_ecs_intent(intent, path))
    if _package_declares_s3_private_bucket(manifest):
        issues.extend(_validate_private_s3_intent(intent, path))
    return issues


def _validate_intents(package_root: Path, schema: dict[str, Any], manifest: dict[str, Any]) -> None:
    validator = Draft202012Validator(schema)

    valid_intents = sorted((package_root / "examples").glob("*.intent.toml"))
    valid_intents.extend(sorted((package_root / "tests" / "valid").glob("*.intent.toml")))
    if not valid_intents:
        raise ValidationError(f"Package must include examples or valid intent tests: {_rel(package_root)}")

    for path in valid_intents:
        intent = _load_intent(path)
        errors = sorted(validator.iter_errors(intent), key=lambda err: list(err.path))
        if errors:
            raise ValidationError(f"Intent schema validation failed for {_rel(path)}: {errors[0].message}")
        issues = _validate_package_intent(intent, path, manifest)
        if issues:
            raise ValidationError("; ".join(issues))

    invalid_intents = sorted((package_root / "tests" / "invalid").glob("*.intent.toml"))
    for path in invalid_intents:
        intent = _load_intent(path)
        schema_errors = list(validator.iter_errors(intent))
        package_issues = _validate_package_intent(intent, path, manifest)
        if not schema_errors and not package_issues:
            raise ValidationError(f"Invalid intent unexpectedly passed validation: {_rel(path)}")


def _safe_ecs_render_context(intent: dict[str, Any]) -> dict[str, Any]:
    inputs = intent.get("inputs", {})
    service = dict(inputs.get("service", {}))
    service.setdefault("health_check_path", "/")
    network = dict(inputs.get("network", {}))
    container_port = int(service.get("container_port", 8080))
    service_name = service.get("name", "service")
    return {
        "service": service,
        "network": network,
        "listener": {"port": container_port, "protocol": "HTTP"},
        "iam": {
            "task_execution_role_name": f"{service_name}-task-execution",
            "task_execution_policy_arn": "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
        },
        "logs": {"group_name": f"/ecs/{service_name}", "retention_in_days": 30},
        "terraform": {
            "aws_region": "ca-central-1",
            "aws_provider_version": "~> 5.0",
            "variables": {
                "vpc_id": {"default": network.get("vpc_id", "vpc-REPLACE_ME")},
                "private_subnet_ids": {"default": network.get("private_subnet_ids", [])},
                "allowed_internal_cidr_blocks": {"default": network.get("allowed_cidr_blocks", [])},
                "ecs_cluster_arn": {"default": ""},
            },
        },
    }


def _safe_s3_render_context(intent: dict[str, Any]) -> dict[str, Any]:
    inputs = intent.get("inputs", {})
    storage = dict(inputs.get("storage", {}))
    storage.setdefault("tags", {})
    return {
        "storage": storage,
        "terraform": {
            "aws_region": storage.get("aws_region", "ca-central-1"),
            "aws_provider_version": "~> 5.0",
            "variables": {
                "bucket_name": {"default": storage.get("bucket_name", "your-project-private-bucket")},
                "versioning_enabled": {"default": storage.get("versioning_enabled", True)},
                "encryption_enabled": {"default": storage.get("encryption_enabled", True)},
                "block_public_access": {"default": storage.get("block_public_access", True)},
                "force_destroy": {"default": storage.get("force_destroy", False)},
                "tags": {"default": storage.get("tags", {})},
            },
        },
    }


def _safe_render_context(intent: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    if _package_declares_s3_private_bucket(manifest):
        return _safe_s3_render_context(intent)
    return _safe_ecs_render_context(intent)


def _render_templates(package_root: Path, manifest: dict[str, Any]) -> dict[str, str]:
    variants = manifest.get("variants", [])
    if not variants:
        return {}
    template_dir = package_root / variants[0].get("template_dir", "")
    templates = sorted(template_dir.rglob("*.j2"), key=lambda path: path.relative_to(template_dir).as_posix())
    if not templates:
        raise ValidationError(f"No templates found in template_dir: {_rel(template_dir)}")

    for template in templates:
        try:
            rel = template.relative_to(template_dir)
        except ValueError as exc:
            raise ValidationError(f"Template path traversal detected: {_rel(template)}") from exc
        if ".." in PurePosixPath(rel.as_posix()).parts:
            raise ValidationError(f"Template path traversal detected: {_rel(template)}")

    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
    )
    env.filters["hcl"] = _hcl

    valid_intents = sorted((package_root / "tests" / "valid").glob("*.intent.toml"))
    if not valid_intents:
        valid_intents = sorted((package_root / "examples").glob("*.intent.toml"))
    context = _safe_render_context(_load_intent(valid_intents[0]), manifest)

    rendered: dict[str, str] = {}
    for template_path in templates:
        name = template_path.relative_to(template_dir).as_posix()
        output_name = name.removesuffix(".j2")
        rendered[output_name] = env.get_template(name).render(context)
    return rendered


def _scan_rendered_ecs_terraform(terraform: str) -> list[str]:
    failures: list[str] = []
    if re.search(r"assign_public_ip\s*=\s*true", terraform):
        failures.append("assign_public_ip = true is not allowed")
    if "public_subnet_ids" in terraform:
        failures.append("public_subnet_ids references are not allowed")
    if not re.search(r"\binternal\s*=\s*true\b", terraform):
        failures.append("internal ALB setting is missing")
    if 'resource "aws_lb_listener"' not in terraform:
        failures.append("aws_lb_listener is missing")
    if "logConfiguration" not in terraform:
        failures.append("ECS logConfiguration is missing")
    if "execution_role_arn" not in terraform:
        failures.append("ECS execution_role_arn is missing")
    ecs_ingress_public = re.search(
        r'resource\s+"aws_security_group_rule"\s+"[^"]*ecs[^"]*".*?type\s*=\s*"ingress".*?(0\.0\.0\.0/0|::/0)',
        terraform,
        flags=re.DOTALL,
    )
    if ecs_ingress_public:
        failures.append("direct public ECS ingress is not allowed")
    return failures


def _scan_rendered_s3_terraform(terraform: str) -> list[str]:
    failures: list[str] = []
    if 'resource "aws_s3_bucket_public_access_block"' not in terraform:
        failures.append("aws_s3_bucket_public_access_block is missing")
    if 'resource "aws_s3_bucket_server_side_encryption_configuration"' not in terraform:
        failures.append("aws_s3_bucket_server_side_encryption_configuration is missing")
    for flag in (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ):
        if not re.search(rf"\b{flag}\s*=\s*(true|var\.block_public_access)\b", terraform):
            failures.append(f"{flag} must be enabled")
    if "var.block_public_access == true" not in terraform:
        failures.append("block_public_access variable must validate true")
    if "var.encryption_enabled == true" not in terraform:
        failures.append("encryption_enabled variable must validate true")
    if re.search(r'\bacl\s*=\s*"public-(read|read-write)"', terraform):
        failures.append("public S3 ACLs are not allowed")
    if 'resource "aws_s3_bucket_acl"' in terraform:
        failures.append("aws_s3_bucket_acl resources are not allowed")
    if "aws_s3_bucket_website_configuration" in terraform or re.search(r"\bwebsite\s*{", terraform):
        failures.append("S3 website hosting is not allowed")
    public_principal_patterns = (
        re.compile(r'"Principal"\s*:\s*"\*"'),
        re.compile(r'"Principal"\s*:\s*{\s*"AWS"\s*:\s*"\*"'),
        re.compile(r'principals?\s*{[^}]*identifiers\s*=\s*\[[^\]]*"\*"', re.DOTALL),
    )
    if any(pattern.search(terraform) for pattern in public_principal_patterns):
        failures.append("public S3 bucket policies are not allowed")
    return failures


def _scan_rendered_terraform(rendered: dict[str, str], package_root: Path, manifest: dict[str, Any]) -> None:
    terraform = "\n".join(content for name, content in sorted(rendered.items()) if name.endswith(".tf"))
    if not terraform:
        return
    failures: list[str] = []
    if _package_declares_ecs_backend(manifest):
        failures.extend(_scan_rendered_ecs_terraform(terraform))
    if _package_declares_s3_private_bucket(manifest):
        failures.extend(_scan_rendered_s3_terraform(terraform))
    if failures:
        raise ValidationError(f"Terraform static scan failed for {_rel(package_root)}: {'; '.join(failures)}")


def _deterministic_archive_digest(package_root: Path, files: list[Path]) -> str:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as gzip_file:
        with tarfile.open(fileobj=gzip_file, mode="w") as tar:
            for path in sorted(files, key=lambda item: item.relative_to(package_root).as_posix()):
                rel = path.relative_to(package_root).as_posix()
                data = path.read_bytes()
                info = tarfile.TarInfo(rel)
                info.size = len(data)
                info.mtime = 0
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def _validate_deterministic_archive(package_root: Path, files: list[Path]) -> None:
    first = _deterministic_archive_digest(package_root, files)
    second = _deterministic_archive_digest(package_root, files)
    if first != second:
        raise ValidationError(f"Deterministic archive digest mismatch for {_rel(package_root)}")


def validate_repo() -> None:
    with tempfile.TemporaryDirectory(prefix="clovaryn-blueprint-validation-") as temp_dir:
        temp_path = Path(temp_dir).resolve()
        _validate_repository_file_safety()
        for package_root in _discover_package_roots():
            files = _validate_package_file_safety(package_root)
            manifest = _validate_package_metadata(package_root)
            schema = _validate_schema_files(package_root)
            _validate_intents(package_root, schema, manifest)
            rendered = _render_templates(package_root, manifest)
            _scan_rendered_terraform(rendered, package_root, manifest)
            _validate_deterministic_archive(package_root, files)
        if not temp_path.exists():
            raise ValidationError("Temporary validation directory was unexpectedly removed")


def run_self_tests() -> None:
    def expect_error(func, message: str) -> None:
        try:
            func()
        except ValidationError:
            return
        raise ValidationError(f"Self-test failed: {message}")

    assert _is_forbidden_path(Path("main.tf"))
    assert _is_forbidden_path(Path("terraform.tfvars"))
    assert _is_forbidden_path(Path("script.sh"))
    assert _is_forbidden_path(Path("service-account.json"))
    assert _is_allowed_template_source(Path("main.tf.j2"))
    assert _is_allowed_template_source(Path("terraform.tfvars.j2"))
    assert not _is_allowed_template_source(Path("helper.j2"))
    assert _looks_binary(b"abc\x00def")

    valid_variant = {
        "id": "variant",
        "template_dir": "templates/terraform",
        "template_language": "terraform",
        "supported_iac_targets": ["terraform", "opentofu"],
    }
    _validate_variant_target_metadata(REPO_ROOT, valid_variant, dict(valid_variant))
    expect_error(
        lambda: _validate_variant_target_metadata(
            REPO_ROOT,
            {
                "id": "variant",
                "template_dir": "templates/terraform",
                "template_language": "terraform",
                "supported_iac_targets": ["tf"],
            },
        ),
        "target alias was not rejected in public package metadata",
    )
    expect_error(
        lambda: _validate_variant_target_metadata(
            REPO_ROOT,
            {
                "id": "variant",
                "template_dir": "templates/pulumi",
                "template_language": "pulumi",
                "supported_iac_targets": ["opentofu"],
            },
        ),
        "OpenTofu support with non-Terraform template language was not rejected",
    )

    ecs_manifest = {
        "package": {"name": "aws-private-ecs-backend"},
        "families": [{"id": "aws-private-ecs-backend"}],
    }
    s3_manifest = {
        "package": {"name": "aws-s3-private-bucket"},
        "families": [{"id": "aws-s3-private-bucket"}],
    }

    unsafe_ecs_snippets = [
        {"ecs.tf": 'resource "aws_ecs_service" "service" { assign_public_ip = true }'},
        {"network.tf": 'variable "public_subnet_ids" { type = list(string) }'},
        {"alb.tf": 'resource "aws_lb" "service" { internal = false }'},
        {"security_groups.tf": '''
resource "aws_security_group_rule" "ecs_public_ingress" {
  type = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}
'''},
    ]
    for snippet in unsafe_ecs_snippets:
        expect_error(
            lambda snippet=snippet: _scan_rendered_terraform(snippet, REPO_ROOT, ecs_manifest),
            "unsafe ECS Terraform was not rejected",
        )

    unsafe_s3_snippets = [
        {"s3.tf": 'resource "aws_s3_bucket" "this" {}'},
        {"s3.tf": 'resource "aws_s3_bucket_acl" "public" { acl = "public-read" }'},
        {
            "s3.tf": '''
resource "aws_s3_bucket_public_access_block" "this" {
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

variable "block_public_access" {
  validation {
    condition = var.block_public_access == true
  }
}
''',
        },
        {
            "s3.tf": '''
resource "aws_s3_bucket_public_access_block" "this" {
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {}

data "aws_iam_policy_document" "public" {
  statement {
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
  }
}

variable "block_public_access" {
  validation {
    condition = var.block_public_access == true
  }
}

variable "encryption_enabled" {
  validation {
    condition = var.encryption_enabled == true
  }
}
''',
        },
    ]
    for snippet in unsafe_s3_snippets:
        expect_error(
            lambda snippet=snippet: _scan_rendered_terraform(snippet, REPO_ROOT, s3_manifest),
            "unsafe S3 Terraform was not rejected",
        )

    with tempfile.TemporaryDirectory(prefix="clovaryn-validator-self-test-") as temp_dir:
        package_root = Path(temp_dir) / "package"
        package_root.mkdir()
        (package_root / "safe.txt").write_text("safe", encoding="utf-8")
        files = [package_root / "safe.txt"]
        first = _deterministic_archive_digest(package_root, files)
        second = _deterministic_archive_digest(package_root, files)
        if first != second:
            raise ValidationError("Self-test failed: deterministic archive digest changed")

        (package_root / "helper.j2").write_text("hello", encoding="utf-8")
        expect_error(lambda: _validate_package_file_safety(package_root), "unexpected template type was not rejected")

        (package_root / "helper.j2").unlink()
        (package_root / "binary.md").write_bytes(b"abc\x00def")
        expect_error(lambda: _validate_package_file_safety(package_root), "binary file was not rejected")

        (package_root / "binary.md").unlink()
        (package_root / "oversized.tf.j2").write_text("x" * (MAX_TEMPLATE_BYTES + 1), encoding="utf-8")
        expect_error(lambda: _validate_package_file_safety(package_root), "oversized template was not rejected")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate public Clovaryn blueprint packages.")
    parser.add_argument("--self-test", action="store_true", help="Run validator self-tests.")
    args = parser.parse_args()
    try:
        if args.self_test:
            run_self_tests()
        else:
            validate_repo()
    except ValidationError as exc:
        print(f"validation failed: {exc}")
        return 1
    print("validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
