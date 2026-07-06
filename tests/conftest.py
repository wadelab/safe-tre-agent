"""Test session setup.

Starlette's TestClient presents peer host 'testclient'. The restricted-channel
check honours that only when SAFETRE_ALLOW_TEST_CLIENT is set — a deliberate
production-safe default (see safetre_web/channel.py). Enable it for the whole
test session here, before any test module imports the app.
"""

import os

os.environ.setdefault("SAFETRE_ALLOW_TEST_CLIENT", "1")
