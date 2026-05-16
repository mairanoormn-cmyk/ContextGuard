import json
import logging
import os
from datetime import datetime, timezone

from google.oauth2 import service_account
from googleapiclient.discovery import build

logger = logging.getLogger("contextguard")

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
]

SYNTHETIC_APPS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "demo", "synthetic_apps.json"
)


def _load_synthetic_apps() -> list:
    """SRS §10.1: Demo fallback when Workspace admin credentials unavailable."""
    if not os.path.exists(SYNTHETIC_APPS_PATH):
        logger.warning("Synthetic apps file not found: %s", SYNTHETIC_APPS_PATH)
        return []
    with open(SYNTHETIC_APPS_PATH, encoding="utf-8") as f:
        apps = json.load(f)
    now = datetime.now(timezone.utc).isoformat()
    for app in apps:
        app.setdefault("publisher", "Demo Publisher")
        app.setdefault("last_active", app.get("last_active", now))
        app.setdefault("declared_scopes", app.get("declared_scopes", app.get("scopes", [])))
    logger.info("Loaded %d synthetic OAuth apps for demo", len(apps))
    return apps


def _scan_workspace_api() -> list:
    """FR-1.1–1.2: Real Google Workspace Admin SDK enumeration."""
    creds_path = os.getenv("GOOGLE_WORKSPACE_CREDS")
    admin_email = os.getenv("GOOGLE_ADMIN_EMAIL")

    if not creds_path or not os.path.exists(creds_path):
        raise FileNotFoundError(f"Google Workspace credentials not found: {creds_path}")
    if not admin_email:
        raise ValueError("GOOGLE_ADMIN_EMAIL is not set in .env")

    creds = service_account.Credentials.from_service_account_file(creds_path, scopes=SCOPES)
    creds = creds.with_subject(admin_email)
    directory_service = build("admin", "directory_v1", credentials=creds)

    results = directory_service.users().list(customer="my_customer", maxResults=500).execute()
    users = results.get("users", [])
    logger.info("Found %d Workspace users", len(users))

    app_registry: dict[str, dict] = {}

    for user in users:
        user_email = user.get("primaryEmail")
        if not user_email:
            continue
        try:
            tokens_result = directory_service.tokens().list(userKey=user_email).execute()
            tokens = tokens_result.get("items", [])
        except Exception as e:
            logger.warning("Could not fetch tokens for %s: %s", user_email, e)
            continue

        for token in tokens:
            client_id = token.get("clientId")
            if not client_id:
                continue
            scopes = token.get("scopes", [])
            last_active = token.get("lastTimeUsed") or token.get("creationTime")

            if client_id not in app_registry:
                app_registry[client_id] = {
                    "app_id": client_id,
                    "name": token.get("displayText", "Unknown App"),
                    "publisher": token.get("clientId", "Workspace App")[:32],
                    "scopes": list(scopes),
                    "user_count": 0,
                    "last_active": last_active,
                    "declared_scopes": list(scopes),
                }
            else:
                app_registry[client_id]["scopes"] = list(
                    set(app_registry[client_id]["scopes"]) | set(scopes)
                )
                if last_active and (
                    not app_registry[client_id].get("last_active")
                    or last_active > app_registry[client_id]["last_active"]
                ):
                    app_registry[client_id]["last_active"] = last_active

            app_registry[client_id]["user_count"] += 1

    return list(app_registry.values())


def scan_oauth_apps() -> list:
    """
    FR-1.1: Enumerate OAuth apps — Workspace API or synthetic demo data.
    """
    use_synthetic = os.getenv("OAUTH_USE_SYNTHETIC", "").lower() in ("1", "true", "yes")

    if use_synthetic:
        # If no workspace is connected, return an empty list as requested by the user
        return []

    try:
        return _scan_workspace_api()
    except Exception as e:
        logger.error("Workspace scan failed: %s", e)
        return []
