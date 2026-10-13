"""Language adapters. `get_adapter` selects one by name; `for_file` by extension."""

from proofhound.adapters.base import LanguageAdapter
from proofhound.adapters.javascript import JavaScriptAdapter
from proofhound.adapters.python import PythonAdapter

_ADAPTERS: dict[str, LanguageAdapter] = {
    "javascript": JavaScriptAdapter(),
    "python": PythonAdapter(),
}


def get_adapter(language: str) -> LanguageAdapter:
    try:
        return _ADAPTERS[language]
    except KeyError:
        raise ValueError(f"no adapter for language: {language}") from None
