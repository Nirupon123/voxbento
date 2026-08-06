"""Tests for the admin panel routes (Phase 3, Step 4).

Covers:
- Admin login/logout flow
- require_admin() guard (403 without cookie)
- CRUD operations for events, rooms, booths
- Dashboard with live status
- Booth detail with WHEP URL and participant roster
"""

from __future__ import annotations

import os

os.environ["BOOTH_ACCESS_TOKEN"] = ""
os.environ["ADMIN_PASSWORD"] = "test-admin-pass"

from datetime import datetime, timedelta, timezone

import pytest

from portal.auth import create_admin_token, decode_token
from portal.config import settings

settings.admin_password = "test-admin-pass"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def setup_db():
    """Set up an in-memory database for the FastAPI app."""
    from portal.database import configure, dispose, init_db

    configure("sqlite+aiosqlite://")
    await init_db()
    yield
    await dispose()


@pytest.fixture
def admin_cookie():
    """Return a dict with the admin_token cookie for authenticated requests."""
    token = create_admin_token()
    return {"admin_token": token}


@pytest.fixture
async def seed_event():
    """Seed an event, room, and booth."""
    from portal.database import create_booth, create_event, create_room, get_session

    async with get_session() as s:
        event = await create_event(s, slug="testcon", display_name="TestCon 2026")
        room = await create_room(s, event_id=event.id, display_name="Main Hall")
        booth = await create_booth(
            s,
            event_id=event.id,
            room_id=room.id,
            language_code="en",
            language_name="English",
        )
    return event, room, booth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client():
    from httpx import ASGITransport, AsyncClient

    from fastapi_app import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ---------------------------------------------------------------------------
# Login / Logout tests
# ---------------------------------------------------------------------------


class TestAdminLogin:
    @pytest.mark.anyio
    async def test_login_page_renders(self):
        async with _client() as c:
            resp = await c.get("/admin/login")
        assert resp.status_code == 200
        assert b"Admin" in resp.content

    @pytest.mark.anyio
    async def test_login_with_correct_password(self):
        async with _client() as c:
            resp = await c.post(
                "/admin/login",
                data={"password": "test-admin-pass"},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin/"
        assert "admin_token" in resp.headers.get("set-cookie", "")

    @pytest.mark.anyio
    async def test_login_with_wrong_password(self):
        async with _client() as c:
            resp = await c.post(
                "/admin/login",
                data={"password": "wrong"},
                follow_redirects=False,
            )
        assert resp.status_code == 403
        assert b"Invalid password" in resp.content

    @pytest.mark.anyio
    async def test_logout_clears_cookie(self):
        async with _client() as c:
            resp = await c.get("/admin/logout", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/admin/login"


# ---------------------------------------------------------------------------
# Guard tests
# ---------------------------------------------------------------------------


class TestRequireAdmin:
    @pytest.mark.anyio
    async def test_dashboard_requires_auth(self):
        async with _client() as c:
            resp = await c.get("/admin/", follow_redirects=False)
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_event_list_requires_auth(self):
        async with _client() as c:
            resp = await c.get("/admin/events/", follow_redirects=False)
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_dashboard_with_valid_cookie(self, admin_cookie):
        async with _client() as c:
            resp = await c.get("/admin/", cookies=admin_cookie)
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_invalid_cookie_rejected(self):
        async with _client() as c:
            resp = await c.get("/admin/", cookies={"admin_token": "garbage"})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Home page
# ---------------------------------------------------------------------------


class TestHomePage:
    @pytest.mark.anyio
    async def test_home_renders(self):
        async with _client() as c:
            resp = await c.get("/")
        assert resp.status_code == 200
        assert b"VoxBento" in resp.content

    @pytest.mark.anyio
    async def test_home_shows_events(self, seed_event):
        async with _client() as c:
            resp = await c.get("/")
        assert resp.status_code == 200
        assert b"TestCon 2026" in resp.content

    @pytest.mark.anyio
    async def test_home_shows_listener_links(self, seed_event):
        async with _client() as c:
            resp = await c.get("/")
        assert resp.status_code == 200
        assert b"/listener/testcon" in resp.content


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestDashboard:
    @pytest.mark.anyio
    async def test_dashboard_empty(self, admin_cookie):
        async with _client() as c:
            resp = await c.get("/admin/", cookies=admin_cookie)
        assert resp.status_code == 200
        assert b"set up your first event" in resp.content

    @pytest.mark.anyio
    async def test_dashboard_shows_events(self, admin_cookie, seed_event):
        async with _client() as c:
            resp = await c.get("/admin/", cookies=admin_cookie)
        assert resp.status_code == 200
        assert b"TestCon 2026" in resp.content
        assert b"English" in resp.content


# ---------------------------------------------------------------------------
# Event CRUD
# ---------------------------------------------------------------------------


class TestEventCRUD:
    @pytest.mark.anyio
    async def test_event_list(self, admin_cookie, seed_event):
        async with _client() as c:
            resp = await c.get("/admin/events/", cookies=admin_cookie)
        assert resp.status_code == 200
        assert b"testcon" in resp.content

    @pytest.mark.anyio
    async def test_create_event(self, admin_cookie):
        async with _client() as c:
            resp = await c.post(
                "/admin/events/",
                data={"slug": "newcon", "display_name": "NewCon 2026"},
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 303
        # Verify it was created
        async with _client() as c:
            resp = await c.get("/admin/events/", cookies=admin_cookie)
        assert b"NewCon 2026" in resp.content

    @pytest.mark.anyio
    async def test_event_detail(self, admin_cookie, seed_event):
        event, _, _ = seed_event
        async with _client() as c:
            resp = await c.get(f"/admin/events/{event.id}/", cookies=admin_cookie)
        assert resp.status_code == 200
        assert b"TestCon 2026" in resp.content
        assert b"Main Hall" in resp.content

    @pytest.mark.anyio
    async def test_event_detail_shows_booth_links(self, admin_cookie, seed_event):
        event, _, _ = seed_event
        async with _client() as c:
            resp = await c.get(f"/admin/events/{event.id}/", cookies=admin_cookie)
        assert b"/interpreter/testcon/en" in resp.content

    @pytest.mark.anyio
    async def test_delete_event(self, admin_cookie, seed_event):
        event, _, _ = seed_event
        async with _client() as c:
            resp = await c.post(
                f"/admin/events/{event.id}/delete",
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 303
        # Verify deleted
        async with _client() as c:
            resp = await c.get("/admin/events/", cookies=admin_cookie)
        assert b"testcon" not in resp.content

    @pytest.mark.anyio
    async def test_event_not_found(self, admin_cookie):
        async with _client() as c:
            resp = await c.get("/admin/events/99999/", cookies=admin_cookie)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Room CRUD
# ---------------------------------------------------------------------------


class TestRoomCRUD:
    @pytest.mark.anyio
    async def test_room_list(self, admin_cookie, seed_event):
        event, _, _ = seed_event
        async with _client() as c:
            resp = await c.get(f"/admin/events/{event.id}/rooms/", cookies=admin_cookie)
        assert resp.status_code == 200
        assert b"Main Hall" in resp.content

    @pytest.mark.anyio
    async def test_create_room(self, admin_cookie, seed_event):
        event, _, _ = seed_event
        async with _client() as c:
            resp = await c.post(
                f"/admin/events/{event.id}/rooms/",
                data={"display_name": "Track B"},
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 303
        async with _client() as c:
            resp = await c.get(f"/admin/events/{event.id}/rooms/", cookies=admin_cookie)
        assert b"Track B" in resp.content

    @pytest.mark.anyio
    async def test_room_detail(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/",
                cookies=admin_cookie,
            )
        assert resp.status_code == 200
        assert b"Main Hall" in resp.content
        assert b"English" in resp.content

    @pytest.mark.anyio
    async def test_room_detail_shows_interpreter_urls(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/",
                cookies=admin_cookie,
            )
        assert b"/interpreter/testcon/en" in resp.content
        assert b"/listener/testcon" in resp.content

    @pytest.mark.anyio
    async def test_room_detail_shows_audio_delay_setting(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/",
                cookies=admin_cookie,
            )
        assert resp.status_code == 200
        assert b"Audio Synchronization Delay (ms)" in resp.content
        assert b'name="audio_delay_ms"' in resp.content

    @pytest.mark.anyio
    async def test_update_room_audio_delay(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.post(
                f"/admin/events/{event.id}/rooms/{room.id}/edit",
                data={
                    "display_name": "Main Hall",
                    "jitsi_url": "",
                    "relay_booth_id": "none",
                    "audio_delay_ms": "2500",
                },
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 303

        from portal.database import get_room_by_id, get_session

        async with get_session() as s:
            updated = await get_room_by_id(s, room.id)
            assert updated is not None
            assert updated.audio_delay_ms == 2500

    @pytest.mark.anyio
    async def test_update_room_audio_delay_rejects_out_of_range(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.post(
                f"/admin/events/{event.id}/rooms/{room.id}/edit",
                data={
                    "display_name": "Main Hall",
                    "jitsi_url": "",
                    "relay_booth_id": "none",
                    "audio_delay_ms": "10001",
                },
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_listener_page_includes_room_audio_delay(self, seed_event):
        event, room, _ = seed_event

        from portal.database import get_session

        async with get_session() as s:
            db_event = await s.get(type(event), event.id)
            db_room = await s.get(type(room), room.id)
            assert db_event is not None
            assert db_room is not None
            db_event.listener_join_code = "ROOM42"
            db_room.audio_delay_ms = 5000

        async with _client() as c:
            resp = await c.get(f"/listener/{event.slug}?code=ROOM42")

        assert resp.status_code == 200
        assert b'"audio_delay_ms": 5000' in resp.content

    @pytest.mark.anyio
    async def test_listener_room_audio_delay_endpoint_reflects_updates(self, seed_event):
        event, room, _ = seed_event

        from portal.database import get_session

        async with get_session() as s:
            db_event = await s.get(type(event), event.id)
            db_room = await s.get(type(room), room.id)
            assert db_event is not None
            assert db_room is not None
            db_event.listener_join_code = "ROOM42"
            db_room.audio_delay_ms = 2000

        async with _client() as c:
            resp = await c.get(f"/listener/{event.slug}/rooms/{room.id}/audio-delay?code=ROOM42")

        assert resp.status_code == 200
        assert resp.json() == {"audio_delay_ms": 2000}

    @pytest.mark.anyio
    async def test_delete_room(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.post(
                f"/admin/events/{event.id}/rooms/{room.id}/delete",
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 303


# ---------------------------------------------------------------------------
# Booth CRUD
# ---------------------------------------------------------------------------


class TestBoothCRUD:
    @pytest.mark.anyio
    async def test_booth_list(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/",
                cookies=admin_cookie,
            )
        assert resp.status_code == 200
        assert b"English" in resp.content

    @pytest.mark.anyio
    async def test_create_booth(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.post(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/",
                data={"language_code": "fr", "language_name": "French"},
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 303
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/",
                cookies=admin_cookie,
            )
        assert b"French" in resp.content

    @pytest.mark.anyio
    async def test_booth_detail(self, admin_cookie, seed_event):
        event, room, booth = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/{booth.id}/",
                cookies=admin_cookie,
            )
        assert resp.status_code == 200
        assert b"English" in resp.content
        assert b"whep" in resp.content.lower()

    @pytest.mark.anyio
    async def test_booth_detail_shows_whep_url(self, admin_cookie, seed_event):
        event, room, booth = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/{booth.id}/",
                cookies=admin_cookie,
            )
        assert b"testcon/en/whep" in resp.content

    @pytest.mark.anyio
    async def test_booth_detail_shows_mediamtx_path(self, admin_cookie, seed_event):
        event, room, booth = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/{booth.id}/",
                cookies=admin_cookie,
            )
        assert b"testcon/en" in resp.content

    @pytest.mark.anyio
    async def test_booth_detail_shows_invite_tokens(self, admin_cookie, seed_event):
        event, room, booth = seed_event
        from portal.database import create_invite_token, get_session

        async with get_session() as s:
            await create_invite_token(s, booth_id=booth.id, role="interpreter", label="Alice")

        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/{booth.id}/",
                cookies=admin_cookie,
            )
        assert b"Alice" in resp.content
        assert b"interpreter" in resp.content.lower()

    @pytest.mark.anyio
    async def test_delete_booth(self, admin_cookie, seed_event):
        event, room, booth = seed_event
        async with _client() as c:
            resp = await c.post(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/{booth.id}/delete",
                cookies=admin_cookie,
                follow_redirects=False,
            )
        assert resp.status_code == 303

    @pytest.mark.anyio
    async def test_booth_not_found(self, admin_cookie, seed_event):
        event, room, _ = seed_event
        async with _client() as c:
            resp = await c.get(
                f"/admin/events/{event.id}/rooms/{room.id}/booths/99999/",
                cookies=admin_cookie,
            )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth unit tests
# ---------------------------------------------------------------------------


class TestAdminToken:
    @pytest.mark.anyio
    async def test_create_admin_token_has_admin_claim(self, setup_db):
        token = create_admin_token()
        payload = decode_token(token)
        assert payload["admin"] is True
        assert "exp" in payload
        assert "iat" in payload

    @pytest.mark.anyio
    async def test_admin_token_is_valid_jwt(self, setup_db):
        token = create_admin_token()
        payload = decode_token(token)
        assert isinstance(payload, dict)

# ---------------------------------------------------------------------------
# API Key Tests
# ---------------------------------------------------------------------------

class TestAPIKeyBOLA:
    @pytest.mark.anyio
    async def test_api_key_bola_protection(self, setup_db):
        from portal.auth import create_user_token
        from portal.database import create_api_key, create_event, create_user, get_session, set_event_membership

        async with get_session() as session:
            # Create two events
            event1 = await create_event(session, slug="event1", display_name="Event 1")
            event2 = await create_event(session, slug="event2", display_name="Event 2")

            # Create a user who is only admin of Event 1
            user1 = await create_user(session, email="user1@example.com", display_name="User 1")
            await set_event_membership(session, user_id=user1.id, event_id=event1.id, role="event_owner")

            # Create an API key in Event 2
            api_key2, _ = await create_api_key(session, event2.id, name="Event 2 Key")
            key_id = api_key2.id

        token = create_user_token(user_id=user1.id, email=user1.email)

        async with _client() as c:
            c.cookies.set("user_token", token)

            # Try to access Event 2's API Keys
            res_list = await c.get(f"/admin/api/events/{event2.id}/api-keys")
            assert res_list.status_code == 403

            res_post = await c.post(f"/admin/api/events/{event2.id}/api-keys", json={"name": "hacked"})
            assert res_post.status_code == 403

            res_delete = await c.delete(f"/admin/api/events/{event2.id}/api-keys/{key_id}")
            assert res_delete.status_code == 403


class TestAPIKeyCRUD:
    @pytest.mark.anyio
    async def test_api_key_lifecycle(self, setup_db):
        from portal.auth import create_user_token
        from portal.database import create_event, create_user, get_session, set_event_membership

        async with get_session() as session:
            event = await create_event(session, slug="event-api", display_name="Event API")
            user = await create_user(session, email="apiadmin@example.com", display_name="API Admin")
            await set_event_membership(session, user_id=user.id, event_id=event.id, role="event_owner")
            event_id = event.id
            user_id = user.id
            user_email = user.email

        token = create_user_token(user_id=user_id, email=user_email)

        async with _client() as c:
            c.cookies.set("user_token", token)

            # Initially empty
            res = await c.get(f"/admin/api/events/{event_id}/api-keys")
            assert res.status_code == 200
            assert res.json() == []

            # Create API key
            res = await c.post(f"/admin/api/events/{event_id}/api-keys", json={"name": "Integration Key"})
            assert res.status_code == 200
            data = res.json()
            assert data["name"] == "Integration Key"
            assert "raw_key" in data
            assert data["raw_key"].startswith("vb_")

            key_id = data["id"]

            # Prevent duplicate name
            res_dup = await c.post(f"/admin/api/events/{event_id}/api-keys", json={"name": "Integration Key"})
            assert res_dup.status_code == 400
            assert "already exists" in res_dup.json()["detail"]

            # Prevent blank name
            res_blank = await c.post(f"/admin/api/events/{event_id}/api-keys", json={"name": "   "})
            assert res_blank.status_code == 400
            assert "cannot be blank" in res_blank.json()["detail"]

            # List keys (should contain 1)
            res = await c.get(f"/admin/api/events/{event_id}/api-keys")
            assert res.status_code == 200
            keys = res.json()
            assert len(keys) == 1
            assert keys[0]["id"] == key_id
            assert keys[0]["name"] == "Integration Key"
            assert "raw_key" not in keys[0]

            # Revoke key
            res_del = await c.delete(f"/admin/api/events/{event_id}/api-keys/{key_id}")
            assert res_del.status_code == 200

            # List keys (should be empty again)
            res = await c.get(f"/admin/api/events/{event_id}/api-keys")
            assert res.status_code == 200
            assert res.json() == []

            # Duplicate name is now allowed since the old one is revoked
            res_remake = await c.post(f"/admin/api/events/{event_id}/api-keys", json={"name": "Integration Key"})
            assert res_remake.status_code == 200
            assert res_remake.json()["name"] == "Integration Key"
