from __future__ import annotations

import uuid

from redis import Redis

from app import create_app, redis_connection_options
from app.extensions import limiter


def assert_connection_policy(client: Redis) -> None:
    options = client.connection_pool.connection_kwargs
    assert options["protocol"] == 2
    assert options["legacy_responses"] is True
    assert options["socket_connect_timeout"] == 2.0
    assert options["socket_timeout"] == 5.0
    assert options["socket_keepalive"] is True
    assert options["health_check_interval"] == 30
    assert client.connection_pool.max_connections == 100
    assert options["retry_on_timeout"] is False
    assert options["retry"].get_retries() == 0


def main() -> None:
    app = create_app()
    text_client = app.extensions["redis"]
    session_client = app.extensions["redis_session"]
    assert_connection_policy(text_client)
    assert_connection_policy(session_client)
    assert_connection_policy(limiter.storage.storage)

    suffix = uuid.uuid4().hex
    hash_key = f"ospbank:redis8-smoke:hash:{suffix}"
    session_key = f"session:redis8-smoke:{suffix}"
    rate_key = f"ospbank:redis8-smoke:rate:{suffix}"
    try:
        pipeline = text_client.pipeline()
        pipeline.hset(hash_key, mapping={"state": "ready", "attempts": "1"})
        pipeline.expire(hash_key, 30)
        pipeline.hgetall(hash_key)
        results = pipeline.execute()
        assert results[-1] == {"state": "ready", "attempts": "1"}

        session_client.set(session_key, b"existing-session", ex=30)
        replacement = Redis.from_url(
            app.config["REDIS_URL"],
            decode_responses=False,
            client_name="sitbank-redis8-restart-check",
            **redis_connection_options(app.config),
        )
        try:
            assert replacement.get(session_key) == b"existing-session"
        finally:
            replacement.close()

        assert limiter.storage.incr(rate_key, expiry=30) == 1
        assert limiter.storage.get(rate_key) == 1
    finally:
        text_client.delete(hash_key, rate_key)
        session_client.delete(session_key)
        text_client.close()
        session_client.close()

    print("redis-py 8 compatibility checks passed")


if __name__ == "__main__":
    main()
