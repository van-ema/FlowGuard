from __future__ import annotations

from pathlib import Path
from typing import IO, Any

from .provenance import SECRET_LABEL, Provenance, SourceRef
from .tracked import track_value


class GuardedFile:
    def __init__(self, runtime: Any, path: str | Path, mode: str = "r", **kwargs: Any) -> None:
        self._runtime = runtime
        self._path = Path(path)
        self._handle: IO[Any] = open(self._path, mode, **kwargs)

    def read(self, *args: Any, **kwargs: Any) -> Any:
        value = self._handle.read(*args, **kwargs)
        is_secret = self._runtime.is_secret_path(self._path)

        self._runtime.emitter.emit(
            "file_read",
            path=str(self._path),
            secret=is_secret,
            length=len(value),
        )

        if not is_secret:
            return value

        provenance = Provenance.from_source(
            label=SECRET_LABEL,
            source=SourceRef.file(self._path),
        )
        return track_value(value, provenance)

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> "GuardedFile":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)

