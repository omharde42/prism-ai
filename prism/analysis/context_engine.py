import re
from typing import List, Dict, Any, Optional, Set
from prism.analysis.diff_analyzer import FileDiff


class ContextEngine:
    """Analyzes codebase context, symbol-level changes, change impact, and blast radius."""

    @staticmethod
    def extract_symbols(file_diffs: List[FileDiff]) -> List[Dict[str, Any]]:
        """Extracts changed functions, classes, routes, and imports from diff chunks."""
        symbols: List[Dict[str, Any]] = []

        python_symbol_pattern = r"^\s*(def|class)\s+([A-Za-z0-9_]+)"
        ts_symbol_pattern = r"^\s*(export\s+)?(async\s+)?(function|class|interface|type)\s+([A-Za-z0-9_]+)"
        ts_const_func_pattern = r"^\s*(export\s+)?const\s+([A-Za-z0-9_]+)\s*=\s*\(?"
        route_pattern = r"@\w+\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            for chunk in fdiff.chunks:
                for line_no, line in chunk.added_lines:
                    s_line = line.strip()
                    if not s_line or s_line.startswith("#") or s_line.startswith("//"):
                        continue

                    # Python def / class
                    py_match = re.match(python_symbol_pattern, s_line)
                    if py_match:
                        kind, name = py_match.group(1), py_match.group(2)
                        symbols.append({
                            "symbol": name,
                            "kind": kind,
                            "file": fdiff.new_path,
                            "line": line_no,
                        })
                        continue

                    # TS/JS function / class / interface
                    ts_match = re.match(ts_symbol_pattern, s_line)
                    if ts_match:
                        kind, name = ts_match.group(3), ts_match.group(4)
                        symbols.append({
                            "symbol": name,
                            "kind": kind,
                            "file": fdiff.new_path,
                            "line": line_no,
                        })
                        continue

                    ts_const_match = re.match(ts_const_func_pattern, s_line)
                    if ts_const_match:
                        name = ts_const_match.group(2)
                        symbols.append({
                            "symbol": name,
                            "kind": "function",
                            "file": fdiff.new_path,
                            "line": line_no,
                        })
                        continue

                    # API route
                    route_match = re.search(route_pattern, s_line, re.IGNORECASE)
                    if route_match:
                        method, path = route_match.group(1).upper(), route_match.group(2)
                        symbols.append({
                            "symbol": f"{method} {path}",
                            "kind": "api_route",
                            "file": fdiff.new_path,
                            "line": line_no,
                        })

        return symbols

    @staticmethod
    def calculate_impact(file_diffs: List[FileDiff]) -> Dict[str, Any]:
        """
        Calculates impact details:
        - affected_modules: List[str]
        - blast_radius: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        - sensitive_modules_affected: List[str]
        - impact_summary: str
        """
        modules: Set[str] = set()
        sensitive_modules: Set[str] = set()
        has_auth = False
        has_db_schema = False
        has_payment = False

        total_additions = 0

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            total_additions += fdiff.additions
            parts = fdiff.new_path.split("/")
            mod = parts[0] if len(parts) > 1 else "root"
            modules.add(mod)

            p_lower = fdiff.new_path.lower()
            if any(kw in p_lower for kw in ["auth", "security", "jwt", "session"]):
                has_auth = True
                sensitive_modules.add(fdiff.new_path)
            if any(kw in p_lower for kw in ["migration", "schema", "alembic", "db/"]):
                has_db_schema = True
                sensitive_modules.add(fdiff.new_path)
            if any(kw in p_lower for kw in ["payment", "billing", "stripe", "checkout"]):
                has_payment = True
                sensitive_modules.add(fdiff.new_path)

        # Determine Blast Radius
        if (has_auth and has_db_schema) or len(modules) >= 6 or (has_auth and total_additions > 300):
            blast_radius = "CRITICAL"
        elif has_auth or has_db_schema or has_payment or len(modules) >= 4 or total_additions > 350:
            blast_radius = "HIGH"
        elif len(modules) >= 2 or total_additions > 100:
            blast_radius = "MEDIUM"
        else:
            blast_radius = "LOW"

        summary = (
            f"Blast Radius: {blast_radius}. Touches {len(modules)} module(s) "
            f"({', '.join(sorted(list(modules))[:4])}) with +{total_additions} lines added."
        )

        return {
            "blast_radius": blast_radius,
            "affected_modules": sorted(list(modules)),
            "sensitive_files_affected": sorted(list(sensitive_modules)),
            "impact_summary": summary,
        }

    @staticmethod
    def build_relevant_context(
        file_diffs: List[FileDiff],
        repository_structure: Optional[Dict[str, Any]] = None,
        max_context_chars: int = 4000
    ) -> str:
        """Filters and formats relevant repository context to fit within LLM token budget."""
        symbols = ContextEngine.extract_symbols(file_diffs)
        impact = ContextEngine.calculate_impact(file_diffs)

        lines = [
            f"== REPOSITORY CONTEXT SUMMARY ==",
            f"Blast Radius Level: {impact['blast_radius']}",
            f"Modules Touched: {', '.join(impact['affected_modules'])}",
        ]

        if impact['sensitive_files_affected']:
            lines.append(f"Sensitive Files Touched: {', '.join(impact['sensitive_files_affected'])}")

        if symbols:
            lines.append("\n== CHANGED SYMBOLS DETECTED ==")
            for sym in symbols[:15]:
                lines.append(f" - [{sym['kind'].upper()}] {sym['symbol']} at {sym['file']}:{sym['line']}")

        context_str = "\n".join(lines)
        if len(context_str) > max_context_chars:
            return context_str[:max_context_chars] + "\n... [Context truncated]"
        return context_str
