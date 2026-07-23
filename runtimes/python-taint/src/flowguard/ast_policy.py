from __future__ import annotations

import ast
from dataclasses import dataclass


DISALLOWED_IMPORT_ROOTS = {
    "ctypes",
    "importlib",
    "os",
    "socket",
    "subprocess",
    "sys",
}

ALLOWED_IMPORT_ROOTS = {
    "base64",
    "json",
    "math",
    "re",
    "urllib",
}

DISALLOWED_CALL_NAMES = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "globals",
    "locals",
    "vars",
}

DISALLOWED_DUNDER_NAMES = {
    "__builtins__",
    "__class__",
    "__dict__",
    "__globals__",
    "__mro__",
    "__subclasses__",
}


@dataclass(frozen=True, slots=True)
class AstPolicyViolation(ValueError):
    message: str
    lineno: int | None = None
    col_offset: int | None = None

    def __str__(self) -> str:
        if self.lineno is None:
            return self.message
        return f"{self.message} at {self.lineno}:{self.col_offset or 0}"


def validate_generated_code(code: str) -> ast.Module:
    tree = ast.parse(code, mode="exec")
    _GeneratedCodePolicy().visit(tree)
    return tree


class _GeneratedCodePolicy(ast.NodeVisitor):
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_import(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            raise self._violation("relative imports are not allowed", node)
        self._check_import(node.module or "", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in DISALLOWED_CALL_NAMES:
            raise self._violation(f"call to {node.func.id} is not allowed", node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in DISALLOWED_DUNDER_NAMES:
            raise self._violation(f"access to {node.attr} is not allowed", node)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in DISALLOWED_DUNDER_NAMES:
            raise self._violation(f"access to {node.id} is not allowed", node)
        self.generic_visit(node)

    def _check_import(self, module: str, node: ast.AST) -> None:
        root = module.split(".", 1)[0]
        if root in DISALLOWED_IMPORT_ROOTS:
            raise self._violation(f"import of {module} is not allowed", node)
        if root not in ALLOWED_IMPORT_ROOTS:
            raise self._violation(f"import of {module} is not in the allowlist", node)

    def _violation(self, message: str, node: ast.AST) -> AstPolicyViolation:
        return AstPolicyViolation(
            message=message,
            lineno=getattr(node, "lineno", None),
            col_offset=getattr(node, "col_offset", None),
        )
