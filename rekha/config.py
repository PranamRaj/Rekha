"""Configuration: a tiny .env loader (no dependencies) plus typed getters.

Precedence, highest first:
  1. real environment variables   (export REKHA_PORT=9000 python -m rekha.server)
  2. the .env file next to the project root
  3. the default baked into the call site

Policy lives in manifests.yaml; .env may override individual limits for experiments.
Anything unset falls back to the manifest, so the red-team numbers stay reproducible
with no .env present at all.
"""
import os, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_loaded = False


def load(path=None, override=False):
    """Read KEY=VALUE lines from .env into os.environ. Idempotent."""
    global _loaded
    if _loaded and path is None and not override:
        return
    path = path or os.environ.get("REKHA_ENV_FILE") or os.path.join(ROOT, ".env")
    _loaded = True
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError:
        return                                      # no .env is a supported setup
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        key, sep, val = line.partition("=")
        if not sep:
            continue
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]                         # quoted: keep inline '#' and spaces
        else:
            val = val.split(" #")[0].strip()        # bare: strip trailing comment
        if override:
            os.environ[key] = val
        else:
            os.environ.setdefault(key, val)


def s(key, default=""):
    load()
    v = os.environ.get(key, "")
    return v if v != "" else default


def i(key, default):
    try:
        return int(str(s(key, default)).replace("_", "").replace(",", ""))
    except (TypeError, ValueError):
        return default


def f(key, default):
    try:
        return float(s(key, default))
    except (TypeError, ValueError):
        return default


def b(key, default=False):
    v = str(s(key, "")).strip().lower()
    return default if v == "" else v in ("1", "true", "yes", "on")


def db_path():
    """Live-demo database. Each process wipes and reseeds this file on startup."""
    return s("REKHA_DB_PATH") or os.path.join(tempfile.gettempdir(), "rekha_live.db")


def manifest_path():
    return s("REKHA_POLICY_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifests.yaml")


def approvers():
    """REKHA_APPROVERS="token:name,token:name" -> {token: name}. Demo credentials only."""
    raw = s("REKHA_APPROVERS", "tok-ops-priya:ops_priya,tok-fin-arun:fin_arun")
    out = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        tok, _, name = part.partition(":")
        if tok.strip():
            out[tok.strip()] = (name.strip() or tok.strip())
    return out


def limit_overrides(keys):
    """Return {limit_name: int} for whichever REKHA_<LIMIT> vars are actually set."""
    out = {}
    for k in keys:
        v = s("REKHA_" + k.upper())
        if v != "":
            try:
                out[k] = int(str(v).replace("_", "").replace(",", ""))
            except ValueError:
                pass
    return out
