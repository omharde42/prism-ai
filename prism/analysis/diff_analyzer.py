import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ChangedChunk:
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    added_lines: List[tuple[int, str]] = field(default_factory=list)  # (line_no, line_content)
    deleted_lines: List[tuple[int, str]] = field(default_factory=list)  # (line_no, line_content)


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    is_new: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    is_binary: bool = False
    additions: int = 0
    deletions: int = 0
    chunks: List[ChangedChunk] = field(default_factory=list)


class DiffAnalyzer:
    @staticmethod
    def parse_patch(raw_diff: str) -> List[FileDiff]:
        """Parse git unified diff into structured FileDiff objects."""
        if not raw_diff or not raw_diff.strip():
            return []

        file_diffs: List[FileDiff] = []
        raw_files = re.split(r"^diff --git ", raw_diff, flags=re.MULTILINE)

        for raw_file in raw_files:
            if not raw_file.strip():
                continue

            lines = raw_file.splitlines()
            header_line = lines[0]

            # Support quoted or unquoted git diff headers (e.g. "a/foo bar" "b/foo bar" or a/file b/file)
            quoted_match = re.search(r'^(?:"?a/(.*?)"?)\s+(?:"?b/(.*?)"?)$', header_line)
            if quoted_match:
                old_path = quoted_match.group(1).strip('"')
                new_path = quoted_match.group(2).strip('"')
            else:
                paths = re.findall(r"a/(.*?) b/(.*)", header_line)
                old_path = paths[0][0] if paths else "unknown"
                new_path = paths[0][1] if paths else "unknown"

            file_diff = FileDiff(old_path=old_path, new_path=new_path)

            if "Binary files" in raw_file:
                file_diff.is_binary = True
                file_diffs.append(file_diff)
                continue

            if "new file mode" in raw_file:
                file_diff.is_new = True
            elif "deleted file mode" in raw_file:
                file_diff.is_deleted = True
            elif "similarity index" in raw_file or "rename from" in raw_file:
                file_diff.is_renamed = True

            current_chunk: Optional[ChangedChunk] = None
            current_new_line_no = 0
            current_old_line_no = 0

            for line in lines:
                if line.startswith("@@"):
                    # Hunk header: @@ -old_start,old_lines +new_start,new_lines @@
                    hunk_match = re.search(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
                    if hunk_match:
                        old_start = int(hunk_match.group(1))
                        old_lines = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                        new_start = int(hunk_match.group(3))
                        new_lines = int(hunk_match.group(4)) if hunk_match.group(4) else 1

                        current_chunk = ChangedChunk(
                            old_start=old_start,
                            old_lines=old_lines,
                            new_start=new_start,
                            new_lines=new_lines,
                        )
                        file_diff.chunks.append(current_chunk)
                        current_old_line_no = old_start
                        current_new_line_no = new_start
                    continue

                if current_chunk is not None:
                    if line.startswith("+"):
                        content = line[1:]
                        current_chunk.added_lines.append((current_new_line_no, content))
                        file_diff.additions += 1
                        current_new_line_no += 1
                    elif line.startswith("-"):
                        content = line[1:]
                        current_chunk.deleted_lines.append((current_old_line_no, content))
                        file_diff.deletions += 1
                        current_old_line_no += 1
                    elif not line.startswith("\\"):
                        current_old_line_no += 1
                        current_new_line_no += 1

            file_diffs.append(file_diff)

        return file_diffs
