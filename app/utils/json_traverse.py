from typing import Any, Iterator


def traverse_json(obj: Any, path: str = "$") -> Iterator[tuple[str, Any]]:
    yield path, obj
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}"
            yield from traverse_json(value, child_path)
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            child_path = f"{path}[{idx}]"
            yield from traverse_json(value, child_path)


def get_field_name(path: str) -> str | None:
    if not path or path == "$":
        return None
    last_dot = path.rfind(".")
    last_bracket = path.rfind("[")
    if last_dot == -1 and last_bracket == -1:
        return path[1:] if path.startswith("$") else path
    if last_dot > last_bracket:
        return path[last_dot + 1:]
    if last_bracket > 0:
        prev_dot = path.rfind(".", 0, last_bracket)
        if prev_dot == -1:
            return None
        return path[prev_dot + 1:last_bracket]
    return None


def extract_json_text(obj: Any) -> list[tuple[str, str, int]]:
    results = []

    def _walk(node: Any, path: str, offset: int) -> int:
        if isinstance(node, str):
            results.append((path, node, offset))
            return offset + len(node)
        if isinstance(node, dict):
            total = 0
            for key, value in node.items():
                child_path = f"{path}.{key}"
                total += _walk(value, child_path, offset + total)
            return total
        if isinstance(node, list):
            total = 0
            for idx, value in enumerate(node):
                child_path = f"{path}[{idx}]"
                total += _walk(value, child_path, offset + total)
            return total
        if isinstance(node, (int, float, bool)) or node is None:
            return len(str(node)) if node is not None else 4
        return 0

    _walk(obj, "$", 0)
    return results
