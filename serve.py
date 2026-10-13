"""
Production server for Windows, Linux and macOS:

    python serve.py

Reads the same .env as the app. Useful settings (all optional):
    HOST=127.0.0.1         interface to listen on. Keep 127.0.0.1 when a proxy (Caddy/nginx) is in front of it.
    PORT=8000
    THREADS=8              worker threads inside the ONE process (don't run several processes: see wsgi.py)
    TRUST_PROXY_HOPS=1     how many reverse proxies sit in front (0 = none, e.g. testing directly on localhost)
    TRUSTED_PROXY_IP=127.0.0.1   address the proxy connects from (default: the same machine)

WHY NOT just `waitress-serve ...`?  waitress silently DISCARDS the X-Forwarded-For / X-Forwarded-Proto headers
unless it is told which proxy to trust. Without that, every voter looks like the proxy's IP (the per-IP rate limits
then throttle all voters together) and the app can't tell the connection is HTTPS (no HSTS). This launcher sets it up.
"""
import os

MAX_BODY_BYTES = 10 * 1024 * 1024        # the app allows 8 MB (photos); cut off bigger uploads at the door


def waitress_settings(proxy_hops, env=None):
    """The keyword arguments for waitress.serve(), derived from the environment. Pure, so it is unit-tested."""
    env = os.environ if env is None else env
    kw = dict(host=env.get("HOST", "127.0.0.1"), port=int(env.get("PORT", "8000")),
              threads=int(env.get("THREADS", "8")), ident="deshgarv", max_request_body_size=MAX_BODY_BYTES)
    if proxy_hops > 0:
        kw.update(
            trusted_proxy=env.get("TRUSTED_PROXY_IP", "127.0.0.1"),     # only THIS address may set X-Forwarded-*
            trusted_proxy_count=proxy_hops,                              # ignore any extra hops a client invents
            trusted_proxy_headers={"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"},
            clear_untrusted_proxy_headers=True, log_untrusted_proxy_headers=True)
    return kw


def main():
    from waitress import serve

    from wsgi import application          # builds the app, prints the banner, starts the model warm-up
    kw = waitress_settings(application.config["TRUST_PROXY_HOPS"])
    print(f"[serve] listening on http://{kw['host']}:{kw['port']}  (threads={kw['threads']})")
    import sms_gateway
    if sms_gateway.provider_name() == "firebase":
        print("[serve] Firebase checks the address in your browser's address bar: it must be listed under Firebase console >\n"
              "        Authentication > Settings > Authorized domains. Open the site with exactly that name.")
    serve(application, **kw)


if __name__ == "__main__":
    main()
