set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mapfile -t rs_files < <(git ls-files '*.rs')

if [ "${#rs_files[@]}" -eq 0 ]; then
    echo "clean-room gate: OK (no Rust files tracked)"
    exit 0
fi

if python3 tools/clean-room-check.py "${rs_files[@]}"; then
    echo "clean-room gate: OK (${#rs_files[@]} Rust files clean)"
    exit 0
else
    echo ""
    echo "=================================================================="
    echo "clean-room gate FAILED"
    echo "only '// SAFETY:' and '/// # Safety' comments are allowed,"
    echo "and they must not name-drop clean-room terms"
    echo "=================================================================="
    exit 1
fi
