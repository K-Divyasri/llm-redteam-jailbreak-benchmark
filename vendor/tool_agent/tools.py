"""The four tools the assistant can call.

A "tool" here is just a normal Python function plus a description of how to call
it. The model never runs these — it only ever *asks* for them by name with some
arguments; your code (the agent loop) actually runs them and hands back the
result. That separation is the whole safety story: the model can request
`do_math("2+2")`, but it can't reach into your machine and do anything you didn't
expose as a tool.

Each function here:
  - takes plain arguments and returns a short string (what the model reads back),
  - validates its own input and returns a friendly error string on bad input
    (rather than raising) so one bad tool call doesn't crash the whole agent,
  - has a matching JSON schema over in schemas.py that tells the model how to call it.
"""

from __future__ import annotations

import ast
import operator
import re
import sqlite3
from pathlib import Path

# Where the bundled SQLite database and search corpus live (made by generate_data.py).
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "company.db"


# --------------------------------------------------------------------------- #
# Tool 1: do_math — a SAFE calculator (never uses eval)
# --------------------------------------------------------------------------- #

# We evaluate arithmetic by walking Python's own parse tree and only allowing a
# fixed set of operations. This is the standard way to "run maths from a string"
# without the catastrophic risk of eval(), which would run ANY Python.
_ALLOWED_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_ALLOWED_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval_node(node: ast.AST) -> float:
    if isinstance(node, ast.Constant):  # a plain number
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("only numbers are allowed")
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BINOPS:
        return _ALLOWED_BINOPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNARY:
        return _ALLOWED_UNARY[type(node.op)](_eval_node(node.operand))
    raise ValueError("unsupported expression")


def do_math(expression: str) -> str:
    """Evaluate a basic arithmetic expression like '15 * (3 + 2) / 4'.

    Supports + - * / // % ** and parentheses. Anything else (names, function
    calls, imports) is rejected — this is a calculator, not a Python shell.
    """
    expression = str(expression).strip()
    try:
        tree = ast.parse(expression, mode="eval")
        result = _eval_node(tree.body)
    except ZeroDivisionError:
        return "Error: division by zero."
    except Exception:
        return f"Error: '{expression}' is not a valid arithmetic expression."
    # Print ints without a trailing .0 so "4" reads better than "4.0".
    if isinstance(result, float) and result.is_integer():
        result = int(result)
    return f"{expression} = {result}"


# --------------------------------------------------------------------------- #
# Tool 2: get_weather — offline canned data, or real (keyless) Open-Meteo
# --------------------------------------------------------------------------- #

# A tiny built-in table so the tool always returns something sensible offline.
# Deterministic on purpose: the same city always gives the same reading, which is
# what you want for reproducible notebooks and tests.
_CANNED_WEATHER = {
    "london": ("12", "cloudy"),
    "paris": ("15", "clear"),
    "tokyo": ("19", "light rain"),
    "new york": ("8", "windy"),
    "sydney": ("24", "sunny"),
    "reykjavik": ("3", "snow"),
    "cairo": ("31", "hot and clear"),
    "mumbai": ("29", "humid"),
}


def get_weather(city: str, live: bool = False) -> str:
    """Return the current weather for a city.

    Offline (default) it reads a small built-in table. With `live=True` it calls
    Open-Meteo — a genuinely free, no-API-key weather service — so you can see a
    real tool hitting a real API. If the network call fails, it falls back to the
    offline table rather than crashing the agent.
    """
    city = str(city).strip()
    key = city.lower()

    if live:
        try:
            return _live_weather(city)
        except Exception:
            # Network down / city not found — degrade gracefully to canned data.
            pass

    if key in _CANNED_WEATHER:
        temp, desc = _CANNED_WEATHER[key]
        return f"The weather in {city.title()} is {desc}, {temp}C."
    return (
        f"No offline weather on file for {city.title()}. "
        f"(Try one of: {', '.join(sorted(c.title() for c in _CANNED_WEATHER))}, "
        f"or run with live weather enabled.)"
    )


def _live_weather(city: str) -> str:  # pragma: no cover - needs the network
    """Hit Open-Meteo for real. No API key required, just internet."""
    import requests

    geo = requests.get(
        "https://geocoding-api.open-meteo.com/v1/search",
        params={"name": city, "count": 1},
        timeout=10,
    ).json()
    if not geo.get("results"):
        raise ValueError(f"city not found: {city}")
    place = geo["results"][0]
    fc = requests.get(
        "https://api.open-meteo.com/v1/forecast",
        params={"latitude": place["latitude"], "longitude": place["longitude"],
                "current": "temperature_2m,weather_code"},
        timeout=10,
    ).json()
    temp = fc["current"]["temperature_2m"]
    return f"The weather in {place['name']}, {place.get('country', '')} is {temp}C (live)."


# --------------------------------------------------------------------------- #
# Tool 3: web_search — keyword search over a small bundled corpus
# --------------------------------------------------------------------------- #

# A handful of short "documents" so search returns something real offline. A real
# deployment would swap this for Tavily/Brave/SerpAPI — see the knowledge folder.
_CORPUS = {
    "python": "Python is a high-level programming language created by Guido van Rossum, first released in 1991.",
    "rag": "Retrieval-augmented generation (RAG) fetches relevant documents, then asks an LLM to answer using them.",
    "embedding": "An embedding is a list of numbers representing text so that similar meanings get similar vectors.",
    "agent": "An AI agent uses a language model to decide which tools to call to accomplish a task, in a loop.",
    "transformer": "The transformer is the neural network architecture behind modern LLMs, introduced in 2017.",
    "http": "HTTP is the protocol web browsers and APIs use to request and send data over the internet.",
    "sqlite": "SQLite is a small, file-based SQL database that needs no separate server process.",
    "json": "JSON is a lightweight text format for structured data, built from objects and arrays.",
}


def web_search(query: str, k: int = 2) -> str:
    """Search a small local corpus and return the best-matching snippets.

    Scores each document by how many of the query's words it contains. Offline and
    deterministic. The real version of this tool would call a web-search API.
    """
    query = str(query).strip()
    # Tokenise to bare words so trailing punctuation ("RAG?") still matches.
    words = {w for w in re.findall(r"[a-z0-9]+", query.lower()) if len(w) > 2}
    if not words:
        return "Error: empty search query."

    scored = []
    for key, text in _CORPUS.items():
        haystack = (key + " " + text).lower()
        score = sum(1 for w in words if w in haystack)
        if score:
            scored.append((score, text))
    scored.sort(key=lambda t: t[0], reverse=True)

    if not scored:
        return f"No results found for '{query}'."
    hits = [text for _, text in scored[:k]]
    return "Search results:\n" + "\n".join(f"- {h}" for h in hits)


# --------------------------------------------------------------------------- #
# Tool 4: query_database — READ-ONLY, parameterised lookups over SQLite
# --------------------------------------------------------------------------- #

# The model supplies a table name and optional filters; it never writes raw SQL.
# We build a parameterised SELECT ourselves, so there's no SQL injection and no way
# to modify or drop anything. (Writing raw SQL is a whole separate project — the
# "SQL Agent" — and needs much stronger guards.)
_ALLOWED_TABLES = {
    "employees": {"columns": {"name", "department", "city", "salary"},
                  "filterable": {"department", "city"}},
    "products": {"columns": {"name", "category", "price", "in_stock"},
                 "filterable": {"category"}},
}


def query_database(table: str, department: str | None = None,
                   city: str | None = None, category: str | None = None) -> str:
    """Look up rows in the bundled company database (read-only).

    `table` is 'employees' or 'products'. The optional filters narrow the results.
    Returns matching rows as text. No writes, no raw SQL — only these safe filters.
    """
    table = str(table).strip().lower()
    if table not in _ALLOWED_TABLES:
        return f"Error: unknown table '{table}'. Try 'employees' or 'products'."
    if not DB_PATH.exists():
        return "Error: database not found. Run `python generate_data.py` first."

    filters = {"department": department, "city": city, "category": category}
    allowed = _ALLOWED_TABLES[table]["filterable"]
    where, params = [], []
    for col, val in filters.items():
        if val is None:
            continue
        if col not in allowed:
            return f"Error: cannot filter '{table}' by '{col}'."
        where.append(f"{col} = ?")
        params.append(str(val))

    sql = f"SELECT * FROM {table}"  # table name validated against the allow-list above
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " LIMIT 20"

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()

    if not rows:
        return f"No rows in '{table}' matched your query."
    lines = [", ".join(f"{k}={r[k]}" for k in r.keys()) for r in rows]
    return f"Found {len(rows)} row(s) in '{table}':\n" + "\n".join(f"- {ln}" for ln in lines)
