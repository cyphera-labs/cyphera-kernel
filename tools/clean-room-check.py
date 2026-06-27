import sys


EXEMPT_PATHS = ("kernel/src/console/font.rs",)

CLEANROOM_WORDS = (
    "linux",
    "freebsd",
    "openbsd",
    "netbsd",
    "bsd",
    "macos",
    "darwin",
    "strace",
    "ltrace",
    "gdb",
    "valgrind",
    "gzdoom",
)

CLEANROOM_PHRASES = (
    "ported from",
    "based on linux",
    "like linux",
)


def is_ident_char(ch):
    return ch.isalnum() or ch == "_"


class Tokenizer:
    def __init__(self, src):
        self.src = src
        self.n = len(src)

    def segments(self):
        src = self.src
        n = self.n
        out = []
        start = 0
        i = 0

        def flush_code(upto):
            if upto > start:
                out.append(("code", src[start:upto], start))

        while i < n:
            ch = src[i]
            two = src[i:i + 2]

            if two == "//":
                flush_code(i)
                j = i + 2
                while j < n and src[j] != "\n":
                    j += 1
                end = j
                if end > i + 2 and src[end - 1] == "\r":
                    end -= 1
                out.append(("line", src[i:end], i))
                i = end
                start = i
                continue

            if two == "/*":
                flush_code(i)
                depth = 1
                j = i + 2
                while j < n and depth > 0:
                    if src[j:j + 2] == "/*":
                        depth += 1
                        j += 2
                    elif src[j:j + 2] == "*/":
                        depth -= 1
                        j += 2
                    else:
                        j += 1
                out.append(("block", src[i:j], i))
                i = j
                start = i
                continue

            if ch == '"':
                i = self._scan_string(i)
                continue

            if ch == "'":
                end = self._scan_char(i)
                if end is not None:
                    i = end
                else:
                    i += 1
                continue

            if ch in ("r", "b"):
                consumed = self._scan_raw_or_byte(i)
                if consumed is not None:
                    i = consumed
                    continue

            i += 1

        flush_code(n)
        return out

    def _scan_string(self, i):
        src = self.src
        n = self.n
        j = i + 1
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
                continue
            if c == '"':
                return j + 1
            j += 1
        return n

    def _scan_char(self, i):
        src = self.src
        n = self.n
        if i + 1 < n and src[i + 1] == "\\":
            j = i + 2
            while j < n and src[j] != "'":
                j += 1
                if j - i > 12:
                    break
            if j < n and src[j] == "'":
                return j + 1
            return None
        if i + 2 < n and src[i + 2] == "'":
            return i + 3
        return None

    def _scan_raw_or_byte(self, i):
        src = self.src
        n = self.n
        j = i
        if src[j] == "b":
            if i > 0 and is_ident_char(src[i - 1]):
                return None
            j += 1
            if j < n and src[j] == '"':
                return self._scan_string(j)
            if j < n and src[j] == "r":
                return self._scan_raw(j)
            return None
        if src[j] == "r":
            if i > 0 and is_ident_char(src[i - 1]):
                return None
            return self._scan_raw(j)
        return None

    def _scan_raw(self, i):
        src = self.src
        n = self.n
        j = i + 1
        hashes = 0
        while j < n and src[j] == "#":
            hashes += 1
            j += 1
        if j < n and src[j] == '"':
            close = '"' + ("#" * hashes)
            k = j + 1
            idx = src.find(close, k)
            if idx == -1:
                return n
            return idx + len(close)
        return None


def line_number_at(src, offset):
    return src.count("\n", 0, offset) + 1


def line_is_doc(text):
    if text.startswith("///") and not text.startswith("////"):
        return "outer"
    if text.startswith("//!"):
        return "inner"
    return None


def line_is_safety_header(text):
    body = text[2:]
    stripped = body.lstrip()
    return stripped.startswith("SAFETY:")


def doc_line_has_safety(text):
    body = text[3:].strip()
    if body.startswith("#"):
        header = body.lstrip("#").strip()
        return header.lower().startswith("safety")
    return False


def block_is_doc(text):
    return text.startswith("/**") or text.startswith("/*!")


def block_has_safety_header(text):
    for raw_line in text.splitlines():
        s = raw_line.strip()
        for opener in ("/**", "/*!", "/*"):
            if s.startswith(opener):
                s = s[len(opener):]
                break
        if s.endswith("*/"):
            s = s[:-2]
        s = s.strip().lstrip("*").strip()
        if s.startswith("#"):
            header = s.lstrip("#").strip()
            if header.lower().startswith("safety"):
                return True
    return False


def continuation_between(text):
    if "\n" not in text:
        return False
    return text.strip() == "" and text.count("\n") == 1


def has_cleanroom_term(text):
    lowered = text.lower()
    for phrase in CLEANROOM_PHRASES:
        if phrase in lowered:
            return phrase
    for word in CLEANROOM_WORDS:
        idx = lowered.find(word)
        while idx != -1:
            before = lowered[idx - 1] if idx > 0 else ""
            after = lowered[idx + len(word)] if idx + len(word) < len(lowered) else ""
            if not is_ident_char(before) and not is_ident_char(after):
                return word
            idx = lowered.find(word, idx + 1)
    return None


def check_source(path, src):
    violations = []
    segs = Tokenizer(src).segments()
    n = len(segs)
    keep_safety = [False] * n

    for idx in range(n):
        kind, text, offset = segs[idx]
        if kind != "line":
            continue
        if line_is_safety_header(text):
            keep_safety[idx] = True
            j = idx + 1
            cur = idx
            while j + 1 <= n - 1:
                gap_kind, gap_text, _ = segs[j]
                if gap_kind != "code" or not continuation_between(gap_text):
                    break
                nxt_kind, nxt_text, _ = segs[j + 1]
                if nxt_kind != "line":
                    break
                if line_is_doc(nxt_text) is not None:
                    break
                keep_safety[j + 1] = True
                cur = j + 1
                j = cur + 1

    doc_run_keep = [False] * n
    idx = 0
    while idx < n:
        kind, text, offset = segs[idx]
        if kind != "line" or line_is_doc(text) != "outer":
            idx += 1
            continue
        run = [idx]
        j = idx + 1
        while j + 1 <= n - 1:
            gap_kind, gap_text, _ = segs[j]
            if gap_kind != "code" or not continuation_between(gap_text):
                break
            nxt_kind, nxt_text, _ = segs[j + 1]
            if nxt_kind != "line" or line_is_doc(nxt_text) != "outer":
                break
            run.append(j + 1)
            j += 2
        has_safety = any(doc_line_has_safety(segs[k][1]) for k in run)
        if has_safety:
            for k in run:
                doc_run_keep[k] = True
        idx = run[-1] + 1

    for idx in range(n):
        kind, text, offset = segs[idx]
        if kind == "line":
            line = line_number_at(src, offset)
            if keep_safety[idx]:
                term = has_cleanroom_term(text)
                if term is not None:
                    violations.append((line, "safety comment name-drops clean-room term '%s'" % term))
                continue
            if doc_run_keep[idx]:
                term = has_cleanroom_term(text)
                if term is not None:
                    violations.append((line, "safety doc comment name-drops clean-room term '%s'" % term))
                continue
            violations.append((line, "comment is not '// SAFETY:' or '/// # Safety'"))
        elif kind == "block":
            line = line_number_at(src, offset)
            if block_is_doc(text) and block_has_safety_header(text):
                term = has_cleanroom_term(text)
                if term is not None:
                    violations.append((line, "safety doc comment name-drops clean-room term '%s'" % term))
                continue
            violations.append((line, "block comment is not a '/// # Safety' doc block"))

    return violations


def is_exempt(path):
    normalized = path.replace("\\", "/")
    for exempt in EXEMPT_PATHS:
        if normalized == exempt or normalized.endswith("/" + exempt):
            return True
    return False


def main(argv):
    paths = argv[1:]
    if not paths:
        sys.stderr.write("usage: python3 tools/clean-room-check.py FILE...\n")
        return 2

    any_violation = False
    for path in paths:
        if not path.endswith(".rs"):
            continue
        if is_exempt(path):
            continue
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as err:
            sys.stderr.write("%s: cannot read: %s\n" % (path, err))
            any_violation = True
            continue
        try:
            src = data.decode("utf-8")
        except UnicodeDecodeError:
            sys.stderr.write("%s: not valid utf-8\n" % path)
            any_violation = True
            continue
        for line, reason in check_source(path, src):
            print("%s:%d: %s" % (path, line, reason))
            any_violation = True

    return 1 if any_violation else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
