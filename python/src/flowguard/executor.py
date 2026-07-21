from __future__ import annotations

import ast
import builtins
import hashlib
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from .ast_policy import ALLOWED_IMPORT_ROOTS, validate_generated_code
from .tracked import provenance_of, track_value


@dataclass(frozen=True, slots=True)
class GeneratedCodeResult:
    code_hash: str
    globals: dict[str, Any]


SAFE_BUILTIN_NAMES = {
    "AssertionError",
    "Exception",
    "False",
    "KeyError",
    "None",
    "RuntimeError",
    "True",
    "ValueError",
    "bool",
    "bytes",
    "dict",
    "enumerate",
    "float",
    "int",
    "isinstance",
    "len",
    "list",
    "max",
    "min",
    "open",
    "print",
    "range",
    "repr",
    "set",
    "sorted",
    "str",
    "sum",
    "tuple",
}


def run_python(
    runtime: Any,
    code: str,
    *,
    inputs: dict[str, Any] | None = None,
) -> GeneratedCodeResult:
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    input_names = sorted((inputs or {}).keys())
    runtime.emitter.emit(
        "generated_code_start",
        code_hash=code_hash,
        input_names=input_names,
    )

    namespace: dict[str, Any] = {}
    try:
        tree = validate_generated_code(code)
        tree = _instrument_generated_code(tree)
        compiled = compile(tree, filename=f"<flowguard-generated:{code_hash[:12]}>", mode="exec")

        with runtime.protect():
            namespace = _execution_globals(runtime, inputs or {})
            exec(compiled, namespace, namespace)
    except Exception as err:
        runtime.emitter.emit(
            "generated_code_error",
            code_hash=code_hash,
            error_type=type(err).__name__,
            message=str(err),
        )
        raise

    public_globals = {
        key: value
        for key, value in namespace.items()
        if not key.startswith("__") and key not in {"flowguard_runtime"}
    }
    runtime.emitter.emit(
        "generated_code_end",
        code_hash=code_hash,
        defined_names=sorted(public_globals),
    )
    return GeneratedCodeResult(code_hash=code_hash, globals=public_globals)


def _execution_globals(runtime: Any, inputs: dict[str, Any]) -> dict[str, Any]:
    safe_builtins = {
        name: getattr(builtins, name)
        for name in SAFE_BUILTIN_NAMES
        if hasattr(builtins, name)
    }
    safe_builtins["__import__"] = _guarded_import

    namespace: dict[str, Any] = {
        "__builtins__": safe_builtins,
        "__flowguard_format_value": _flowguard_format_value,
        "__flowguard_joined_str": _flowguard_joined_str,
        "__flowguard_precision_call": _flowguard_precision_call,
        "__flowguard_runtime": runtime,
    }
    namespace.update(inputs)
    return namespace


def _instrument_generated_code(tree: ast.Module) -> ast.Module:
    instrumented = _GeneratedCodeInstrumenter().visit(tree)
    # New AST nodes need line and column data before compile() accepts the tree.
    return ast.fix_missing_locations(instrumented)


class _GeneratedCodeInstrumenter(ast.NodeTransformer):
    """Rewrites generated code so tainted values survive string formatting."""

    def visit_Call(self, node: ast.Call) -> ast.AST:
        node = self.generic_visit(node)
        operation = _precision_operation_name(node.func)
        if operation is None:
            return node

        return ast.copy_location(
            ast.Call(
                func=ast.Name(id="__flowguard_precision_call", ctx=ast.Load()),
                args=[
                    ast.Name(id="__flowguard_runtime", ctx=ast.Load()),
                    ast.Constant(value=operation),
                    node.func,
                    *node.args,
                ],
                keywords=node.keywords,
            ),
            node,
        )

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        parts: list[ast.AST] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                # Literal f-string text has no taint to preserve.
                parts.append(value)
            elif isinstance(value, ast.FormattedValue):
                # format(value) normally returns plain str and drops taint.
                parts.append(
                    ast.Call(
                        func=ast.Name(id="__flowguard_format_value", ctx=ast.Load()),
                        args=[self.visit(value.value)],
                        keywords=[],
                    )
                )
            else:
                parts.append(self.visit(value))

        # Replace the f-string with a helper that joins text and merges provenance.
        return ast.copy_location(
            ast.Call(
                func=ast.Name(id="__flowguard_joined_str", ctx=ast.Load()),
                args=[ast.List(elts=parts, ctx=ast.Load())],
                keywords=[],
            ),
            node,
        )


def _flowguard_format_value(value: Any) -> Any:
    """Formats one f-string value without losing its provenance."""

    provenance = provenance_of(value)
    text = format(value)
    if _has_provenance(provenance):
        return track_value(
            text,
            provenance.with_transform(
                operation="str.format_value",
                input_type=type(value).__name__,
                output_type="str",
            ),
        )
    return text


def _flowguard_joined_str(parts: list[Any]) -> Any:
    """Joins rewritten f-string parts and keeps merged provenance."""

    text = "".join(str(part) for part in parts)
    provenance = provenance_of(parts)
    if _has_provenance(provenance):
        return track_value(
            text,
            provenance.with_transform(
                operation="str.joined",
                input_type="list",
                output_type="str",
            ),
        )
    return text


def _flowguard_precision_call(
    runtime: Any,
    operation: str,
    func: Any,
    *args: Any,
    **kwargs: Any,
) -> Any:
    input_provenance = provenance_of([args, kwargs])
    result = func(*args, **kwargs)
    output_provenance = provenance_of(result)

    if _has_security_provenance(input_provenance) and not _has_provenance(
        output_provenance
    ):
        runtime.record_precision_lost(
            operation=operation,
            reason="tainted_input_returned_untracked_value",
            provenance=input_provenance,
            input_types=_input_types(args, kwargs),
            output_type=type(result).__name__,
        )

    return result


def _precision_operation_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name) and func.id in {"str", "bytes"}:
        return func.id
    if isinstance(func, ast.Attribute) and func.attr == "dumps":
        path = _attribute_path(func.value)
        if path == ("json",):
            return "json.dumps"
    return None


def _attribute_path(node: ast.AST) -> tuple[str, ...] | None:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        parent = _attribute_path(node.value)
        if parent is not None:
            return (*parent, node.attr)
    return None


def _input_types(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[str, ...]:
    positional = [type(arg).__name__ for arg in args]
    keywords = [f"{key}:{type(value).__name__}" for key, value in sorted(kwargs.items())]
    return tuple([*positional, *keywords])


def _has_provenance(provenance: Any) -> bool:
    return bool(provenance.labels or provenance.sources or provenance.transforms)


def _has_security_provenance(provenance: Any) -> bool:
    return bool(provenance.labels or provenance.sources)


def _guarded_import(
    name: str,
    globals: dict[str, Any] | None = None,
    locals: dict[str, Any] | None = None,
    fromlist: tuple[str, ...] = (),
    level: int = 0,
) -> ModuleType:
    if level:
        raise ImportError("relative imports are not allowed")
    root = name.split(".", 1)[0]
    if root not in ALLOWED_IMPORT_ROOTS:
        raise ImportError(f"import of {name} is not allowed")
    return builtins.__import__(name, globals, locals, fromlist, level)
