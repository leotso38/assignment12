# 🧑‍💻 Copilot Instructions for AI Agents

## Project Overview
- This is a modular Python web application with authentication, calculation, and user management features.
- Main entrypoint: `app/main.py`. Core logic is split into submodules: `auth`, `core`, `models`, `operations`, and `schemas`.
- Database initialization and connection logic is in `app/database.py` and `app/database_init.py`.
- Uses FastAPI (implied by structure and test names), JWT for auth (`app/auth/jwt.py`), and Redis for session/cache (`app/auth/redis.py`).
- Templates are in `templates/` (likely Jinja2 or FastAPI's templating).

## Key Workflows
- **Run app (dev):** `python app/main.py` (or via Docker)
- **Run tests:** `pytest` (tests in `tests/` split into `unit`, `integration`, `e2e`)
- **Build Docker image:** `docker build -t <image-name> .`
- **Run Docker container:** `docker run -it --rm <image-name>`
- **Initialize DB:** `bash init-db.sh` (may require running before app/tests)

## Directory Structure & Patterns
- `app/` contains all source code. Submodules are organized by domain (auth, models, schemas, etc.).
- `tests/` mirrors app structure: unit, integration, e2e. Use correct test type for changes.
- `requirements.txt` for dependencies. Use `pip install -r requirements.txt` after venv activation.
- `Dockerfile` and `docker-compose.yml` for containerization. Use these for reproducible environments.
- `templates/` for HTML views. Backend renders these for web responses.

## Conventions & Integration Points
- **Authentication:** JWT-based, with Redis for token/session management.
- **Configuration:** Centralized in `app/core/config.py`.
- **Schemas:** Pydantic models in `app/schemas/` for request/response validation.
- **Database:** Likely uses SQLAlchemy (check `database.py`). Init via `init-db.sh`.
- **Testing:** Use `pytest`. Place new tests in correct subfolder. Fixtures in `tests/conftest.py`.
- **Environment:** Use Python 3.10+. Virtualenv recommended. Activate before installing packages.
- **Docker:** Optional, but recommended for consistent dev/prod environments.

## Examples
- Add a new API route: place logic in `app/operations/`, schema in `app/schemas/`, update `main.py`.
- Add a new test: place in `tests/unit/` for pure logic, `tests/integration/` for DB/API, `tests/e2e/` for full app flows.
- Update config: change `app/core/config.py`.

## Tips for AI Agents
- Always check for existing patterns in the relevant submodule before adding new code.
- When updating models or schemas, update corresponding tests and fixtures.
- Use Docker for reproducible builds and testing if local setup fails.
- Reference `README.md` for setup and workflow details.

---

_If any section is unclear or missing, ask the user for clarification or examples from their workflow._
