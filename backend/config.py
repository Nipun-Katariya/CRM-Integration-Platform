import os

REQUIRED_ENV_VARS = [
    'AIRTABLE_CLIENT_ID',
    'AIRTABLE_CLIENT_SECRET',
    'HUBSPOT_CLIENT_ID',
    'HUBSPOT_CLIENT_SECRET',
    'NOTION_CLIENT_ID',
    'NOTION_CLIENT_SECRET',
]


def ensure_env_vars():
    """Raise an error listing required env vars that are missing.

    Call this early in startup so the app fails fast with a clear message
    when required credentials are not configured.
    """
    missing = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}.\n"
            f"Create a .env file or set them in your environment. See README.md for details."
        )
