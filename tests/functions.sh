. ./setup.local

success() {
    echo "[OK]"
}

failure() {
    echo "[FAILED]"
    exit 1
}

skipped() {
    echo "[SKIPPED] $*"
}

