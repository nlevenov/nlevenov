import time

import pytest

from socprio.analysis.ml import AlertClassifier
from socprio.api.security import FailureLimiter, SessionSigner, same_origin
from socprio.config import NotifySettings
from socprio.enrich.indicators import NetworkScope
from socprio.ingest.parsers import parse_authlog
from socprio.models import Alert
from socprio.notify import Notifier, escape_mrkdwn
from socprio.storage import _COLUMNS, AlertStore

from helpers import make_alert


def test_session_tokens():
    signer = SessionSigner("k" * 32)
    token = signer.issue()
    assert signer.verify(token)
    assert not SessionSigner("other" * 8).verify(token)
    assert not signer.verify(token[:-1] + ("0" if token[-1] != "0" else "1"))
    assert not signer.verify(None) and not signer.verify("garbage")
    expired = SessionSigner("k" * 32, ttl=-1).issue()
    assert not signer.verify(expired)


def test_failure_limiter():
    limiter = FailureLimiter(max_failures=2, window=60)
    limiter.failure("a")
    assert not limiter.blocked("a")
    limiter.failure("a")
    assert limiter.blocked("a") and not limiter.blocked("b")
    limiter.reset("a")
    assert not limiter.blocked("a")


def test_same_origin():
    assert same_origin("https://soc.example:8443/x", "soc.example:8443")
    assert not same_origin("https://evil.test", "soc.example")
    assert not same_origin(None, "soc.example")


def test_alert_fields_are_validated():
    alert = Alert(timestamp=time.time() + 10 * 86400, source="x", src_ip="1.2.3.4; DROP",
                  dst_ip=" 2001:db8::1 ", src_port=70000, dst_port="443",
                  signature="a\x00b\x1b" + "c" * 5000)
    assert alert.src_ip is None and alert.dst_ip == "2001:db8::1"
    assert alert.src_port is None and alert.dst_port == 443
    assert alert.signature.startswith("abc") and len(alert.signature) == 1024
    assert alert.timestamp.timestamp() < time.time() + 3600
    assert "original_timestamp" in alert.raw


def test_syslog_year_rollover():
    # a timestamp eleven months ahead must belong to last year
    future = time.gmtime(time.time() + 300 * 86400)
    line = time.strftime("%b %d %H:%M:%S", future) + \
        " h sshd[1]: Failed password for x from 203.0.113.1 port 1 ssh2"
    alert = parse_authlog(line)
    assert alert.timestamp.timestamp() < time.time() + 86400


def test_mrkdwn_escaping():
    assert escape_mrkdwn("<!channel> & <https://evil|x>") == \
        "&lt;!channel&gt; &amp; &lt;https://evil|x&gt;"
    notifier = Notifier(NotifySettings(webhook_url="https://hooks.test/x"))
    text = notifier.format(make_alert(signature="<!here> pwned", username="`rm`"))
    assert "<!here>" not in text and "`rm`" not in text


def test_webhook_must_be_https():
    with pytest.raises(ValueError):
        Notifier(NotifySettings(webhook_url="http://hooks.test/x"))


def test_like_wildcards_are_literal():
    store = AlertStore(":memory:")
    for i, sig in enumerate(["100% match", "other"]):
        alert = make_alert(signature=sig, src_ip=f"10.0.0.{i}")
        alert.id = f"a{i}"
        store.save(alert)
    assert store.query(search="%")[1] == 1
    assert store.query(search="_")[1] == 0
    assert store.query(src_ip="10.0.0.1")[1] == 1


def test_row_mapping_matches_schema():
    alert = make_alert()
    alert.id = "x"
    assert tuple(AlertStore._to_row(alert)) == _COLUMNS


def _tiny_classifier(settings):
    from socprio.evaluation import train_from_alerts
    from socprio.ingest.parsers import parse_generic
    from socprio.simulate import generate

    alerts = [a for r in generate(400, seed=1) if (a := parse_generic(r))]
    return train_from_alerts(alerts, settings)[0]


def test_model_signature_is_enforced(settings, tmp_path):
    scope = NetworkScope(settings.internal_networks)
    classifier = _tiny_classifier(settings)
    path = tmp_path / "m.joblib"

    classifier.save(path, signing_key="k1")
    assert AlertClassifier.load(path, scope, signing_key="k1") is not None
    assert AlertClassifier.load(path, scope, signing_key="k2") is None
    assert AlertClassifier.load(path, scope) is None  # HMAC file, no key

    path.write_bytes(path.read_bytes() + b"tampered")
    assert AlertClassifier.load(path, scope, signing_key="k1") is None

    classifier.save(path)
    (tmp_path / "m.joblib.sig").unlink()
    assert AlertClassifier.load(path, scope) is None
