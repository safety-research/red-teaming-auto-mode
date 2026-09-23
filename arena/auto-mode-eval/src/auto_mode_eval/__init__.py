"""Package import installs the prompt-cache patch — see `prompt_cache.install()`.

Here rather than at each call site because the point of patching (over registering a provider)
is that `anthropic/…` keeps working everywhere: a flow spec that had to opt in is a spec that
can forget to, and forgetting costs cache hits silently.
"""

import os
import ssl
from pathlib import Path

from auto_mode_eval import prompt_cache


def _pin_ca_bundle() -> None:
    """Point TLS verification at a single CA *file* rather than a CA *directory*.

    Unset, `httpx2.create_ssl_context` falls back to `truststore`, which verifies against a
    capath. OpenSSL 3 re-enumerates that whole directory on every issuer lookup (openssl#21067),
    and the handshake is a C call on the asyncio thread — so it pins the event loop and a long
    run degrades to a few samples/hr with no visible error. A cafile is parsed once into memory.
    """
    if os.environ.get("SSL_CERT_FILE"):
        return
    cafile = ssl.get_default_verify_paths().openssl_cafile
    if cafile and Path(cafile).is_file():
        os.environ["SSL_CERT_FILE"] = cafile


# must precede construction of any provider http client, hence before prompt_cache
_pin_ca_bundle()
prompt_cache.install()


def main():
    print("Hello from auto-mode-eval!")


if __name__ == "__main__":
    main()
