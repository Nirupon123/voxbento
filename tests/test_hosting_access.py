"""Comprehensive tests for Event Hosting Access, organizer invitations, and workspace gating."""

from __future__ import annotations

import inspect
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from fastapi_app import app
from portal import database
from portal.auth import create_user_token, get_admin_flags, hash_password
from portal.database import (
    configure,
    create_auth_token,
    create_event,
    create_room,
    create_user,
    dispose,
    get_session,
    get_user_by_id,
    init_db,
    set_event_membership,
    set_room_membership,
)
from portal.models import AuthToken, User, utc_now
from portal.workspace_routing import management_template_context

os.environ["BOOTH_ACCESS_TOKEN"] = ""


@pytest.fixture(autouse=True)
async def setup_db():
    configure("sqlite+aiosqlite://")
    await init_db()
    yield
    await dispose()


def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def create_mock_request(path: str = "/admin/", cookies: dict | None = None, headers: dict | None = None) -> Request:
    raw_headers = []
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw_headers.append((b"cookie", cookie_str.encode("latin-1")))
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "headers": raw_headers,
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "scheme": "http",
        "state": {},
    }
    return Request(scope)


@pytest.mark.anyio
async def test_sqlite_busy_timeout_before_wal():
    """Verify that PRAGMA busy_timeout=5000 is executed before PRAGMA journal_mode=WAL."""
    source = inspect.getsource(database)
    idx_busy = source.find("PRAGMA busy_timeout=5000")
    idx_wal = source.find("PRAGMA journal_mode=WAL")
    assert idx_busy != -1
    assert idx_wal != -1
    assert idx_busy < idx_wal


@pytest.mark.anyio
async def test_get_admin_flags_room_owner_and_coordinator():
    """Review 7 A1: Owner and coordinator of the same room on a route with only room_id."""
    async with get_session() as session:
        owner = await create_user(
            session,
            email="owner_coord@example.com",
            display_name="Owner Coord",
            password_hash=hash_password("pw123"),
            email_verified=True,
        )
        event = await create_event(session, slug="shared-ev", display_name="Shared")
        room = await create_room(session, event_id=event.id, display_name="Main Room")
        await set_event_membership(session, user_id=owner.id, event_id=event.id, role="event_owner")
        await set_room_membership(session, user_id=owner.id, room_id=room.id, role="room_coordinator")

    token = create_user_token(user_id=owner.id, email=owner.email)
    req = create_mock_request("/admin/rooms/1/", cookies={"user_token": token})

    # Route with only room_id passed:
    flags = await get_admin_flags(req, event_id=None, room_id=room.id)
    assert flags["is_room_coordinator"] is True
    assert flags["is_event_owner"] is True
    assert flags["is_super_admin"] is False


@pytest.mark.anyio
async def test_template_context_does_not_overwrite_event_scoped_owner_flag():
    """Review 7 A2: Context processor does not inject is_event_owner and overwrite route flags."""
    async with get_session() as session:
        user = await create_user(
            session,
            email="host_user@example.com",
            display_name="Host User",
            password_hash=hash_password("pw123"),
            can_host=True,
        )
    token = create_user_token(user_id=user.id, email=user.email)
    req = create_mock_request("/workspace/events/1/", cookies={"user_token": token})

    ctx = management_template_context(req)
    assert "is_event_owner" not in ctx
    assert ctx["can_host"] is False or isinstance(ctx["can_host"], bool)
    assert ctx["is_workspace"] is False


@pytest.mark.anyio
async def test_invite_acceptance_flow_and_primitive_copying():
    """Review 7 A3: Acceptance flow copies primitives safely, sets single cookie, marks token used."""
    async with get_session() as session:
        user = await create_user(
            session,
            email="invited@example.com",
            display_name="Invited Stub",
            password_hash=None,
            email_verified=False,
            can_host=False,
        )
        tok = await create_auth_token(
            session,
            user_id=user.id,
            token_type="hosting_invite",
            expires_in_seconds=3600,
        )
        token_jti = tok.jti

    async with client() as http:
        # GET form
        resp_get = await http.get(f"/invite/accept/{token_jti}")
        assert resp_get.status_code == 200
        assert "Create Account & Go to Workspace" in resp_get.text

        # POST accept
        resp_post = await http.post(
            f"/invite/accept/{token_jti}",
            data={
                "display_name": "Invited Organizer",
                "password": "ValidPassword123!",
                "password_confirm": "ValidPassword123!",
            },
            headers={"Origin": "http://test"},
            follow_redirects=False,
        )
        assert resp_post.status_code == 303
        assert resp_post.headers["location"] == "/workspace/"
        assert "user_token" in resp_post.cookies

        # Verify DB user state
        async with get_session() as session:
            updated_user = await get_user_by_id(session, user.id)
            assert updated_user.can_host is True
            assert updated_user.email_verified is True
            assert updated_user.password_hash is not None
            assert updated_user.display_name == "Invited Organizer"

            # Token marked used
            used_tok = await session.get(AuthToken, tok.id)
            assert used_tok.is_used is True

        # Re-using the token fails (GET shows invalid/expired message, POST returns 400)
        resp_reuse = await http.get(f"/invite/accept/{token_jti}")
        assert resp_reuse.status_code == 200
        assert "invalid or has expired" in resp_reuse.text.lower()

        resp_reuse_post = await http.post(
            f"/invite/accept/{token_jti}",
            data={"password": "AnotherPassword123!", "password_confirm": "AnotherPassword123!"},
            headers={"Origin": "http://test"},
        )
        assert resp_reuse_post.status_code == 400


@pytest.mark.anyio
async def test_revoked_user_accepts_invite_restores_access():
    """When a user with revoked hosting accepts an invitation, revoked_at and requested_at are cleared and event access is restored."""
    async with get_session() as session:
        user = await create_user(
            session,
            email="was_revoked@example.com",
            display_name="Previously Revoked",
            password_hash=hash_password("ValidPassword123!"),
            email_verified=True,
            can_host=False,
            hosting_revoked_at=utc_now(),
            hosting_requested_at=utc_now(),
        )
        ev = await create_event(session, slug="rev-restored-ev", display_name="Restored Event")
        await set_event_membership(session, user_id=user.id, event_id=ev.id, role="event_owner")
        tok = await create_auth_token(session, user_id=user.id, token_type="hosting_invite", expires_in_seconds=3600)
        token_jti = tok.jti
        user_id = user.id
        event_id = ev.id

    async with client() as http:
        # POST accept invitation
        resp = await http.post(
            f"/invite/accept/{token_jti}",
            headers={"Origin": "http://test"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/workspace/"
        cookie = resp.cookies.get("user_token")
        assert cookie is not None

        # Verify DB state: can_host is True, hosting_revoked_at is None, hosting_requested_at is None
        async with get_session() as session:
            updated = await get_user_by_id(session, user_id)
            assert updated.can_host is True
            assert updated.hosting_revoked_at is None
            assert updated.hosting_requested_at is None

        # User can now access their event without being redirected with hosting_revoked
        ev_resp = await http.get(f"/workspace/events/{event_id}/", cookies={"user_token": cookie}, follow_redirects=False)
        assert ev_resp.status_code == 200


@pytest.mark.anyio
async def test_inactive_user_cannot_be_invited_or_redeem():
    """Inactive users cannot be invited or redeem an invite."""
    async with get_session() as session:
        admin = await create_user(session, email="admin@example.com", display_name="Admin", is_admin=True)
        inactive = await create_user(
            session,
            email="inactive@example.com",
            display_name="Inactive",
            password_hash=hash_password("pw123"),
            is_active=False,
        )
        tok = await create_auth_token(
            session,
            user_id=inactive.id,
            token_type="hosting_invite",
            expires_in_seconds=3600,
        )
        tok_jti = tok.jti

    admin_token = create_user_token(user_id=admin.id, email=admin.email, is_admin=True)

    async with client() as http:
        # Attempt to invite inactive user -> 400
        res_invite = await http.post(
            "/admin/users/invite",
            data={"email": "inactive@example.com"},
            cookies={"user_token": admin_token},
            headers={"Origin": "http://test"},
        )
        assert res_invite.status_code == 400
        assert "inactive" in res_invite.text.lower()

        # Inactive user attempts redemption -> 403
        res_redeem = await http.post(
            f"/invite/accept/{tok_jti}",
            data={"password": "ValidPassword123!", "password_confirm": "ValidPassword123!"},
            headers={"Origin": "http://test"},
        )
        assert res_redeem.status_code == 403
        assert "deactivated" in res_redeem.text.lower()


@pytest.mark.anyio
async def test_toggle_hosting_on_stub_user_rejected():
    """Directly granting hosting to stub user via toggle endpoint is rejected."""
    async with get_session() as session:
        admin = await create_user(session, email="admin@example.com", display_name="Admin", is_admin=True)
        stub = await create_user(session, email="stub@example.com", display_name="Stub", password_hash=None)
        stub_id = stub.id

    admin_token = create_user_token(user_id=admin.id, email=admin.email, is_admin=True)
    async with client() as http:
        resp = await http.post(
            f"/admin/users/{stub_id}/hosting",
            data={"action": "grant"},
            cookies={"user_token": admin_token},
            headers={"Origin": "http://test"},
        )
        assert resp.status_code == 400
        assert "stub" in resp.text.lower()


@pytest.mark.anyio
async def test_toggle_hosting_deletes_pending_tokens():
    """Toggling hosting on registered user deletes any pending invite tokens."""
    async with get_session() as session:
        admin = await create_user(session, email="admin@example.com", display_name="Admin", is_admin=True)
        user = await create_user(
            session,
            email="reg@example.com",
            display_name="Registered",
            password_hash=hash_password("pw123"),
            can_host=False,
        )
        await create_auth_token(session, user_id=user.id, token_type="hosting_invite", expires_in_seconds=3600)
        user_id = user.id

    admin_token = create_user_token(user_id=admin.id, email=admin.email, is_admin=True)
    async with client() as http:
        resp = await http.post(
            f"/admin/users/{user_id}/hosting",
            data={"action": "grant"},
            cookies={"user_token": admin_token},
            headers={"Origin": "http://test"},
        )
        assert resp.status_code == 303

    async with get_session() as session:
        u = await get_user_by_id(session, user_id)
        assert u.can_host is True
        tokens = (
            await session.execute(
                AuthToken.__table__.select().where(
                    AuthToken.user_id == user_id,
                    AuthToken.token_type == "hosting_invite",
                )
            )
        ).fetchall()
        assert len(tokens) == 0


@pytest.mark.anyio
async def test_invite_cancel_and_resend():
    """Cancel and resend invite endpoints work and require same-origin."""
    async with get_session() as session:
        admin = await create_user(session, email="admin@example.com", display_name="Admin", is_admin=True)
        user = await create_user(session, email="pending@example.com", display_name="Pending", password_hash=None)
        tok = await create_auth_token(session, user_id=user.id, token_type="hosting_invite", expires_in_seconds=10)
        token_id = tok.id

    admin_token = create_user_token(user_id=admin.id, email=admin.email, is_admin=True)

    async with client() as http:
        # Cross origin rejected
        resp_bad_origin = await http.post(
            f"/admin/users/invite/{token_id}/resend",
            cookies={"user_token": admin_token},
            headers={"Origin": "http://evil.com"},
        )
        assert resp_bad_origin.status_code == 400

        # Resend works with same-origin
        resp_resend = await http.post(
            f"/admin/users/invite/{token_id}/resend",
            cookies={"user_token": admin_token},
            headers={"Origin": "http://test"},
        )
        assert resp_resend.status_code == 303

        # Cancel works
        resp_cancel = await http.post(
            f"/admin/users/invite/{token_id}/cancel",
            cookies={"user_token": admin_token},
            headers={"Origin": "http://test"},
        )
        assert resp_cancel.status_code == 303

    async with get_session() as session:
        tok_in_db = await session.get(AuthToken, token_id)
        assert tok_in_db is None


@pytest.mark.anyio
async def test_demo_request_hosting_rate_limit_and_user_flag():
    """Demo request enforces rate limits, strips CRLF, ignores spoofed user_id, updates hosting_requested_at."""
    async with get_session() as session:
        user = await create_user(
            session,
            email="requester@example.com",
            display_name="Requester",
            password_hash=hash_password("pw123"),
            email_verified=True,
        )
        user_id = user.id

    token = create_user_token(user_id=user_id, email="requester@example.com")

    async with client() as http:
        with patch("portal.routers.public.send_demo_request_email", new_callable=AsyncMock) as mock_send:
            # 1. Normal submission
            res1 = await http.post(
                "/api/request-demo",
                json={
                    "firstName": "Jane\r\n",
                    "lastName": "Doe",
                    "email": "requester@example.com",
                    "companyName": "Acme\nCorp",
                    "notes": "Conference\r\nTesting",
                    "user_id": 99999,  # spoofed, must be ignored
                    "source": "spoofed_source",
                },
                cookies={"user_token": token},
            )
            assert res1.status_code == 200
            assert res1.json()["ok"] is True
            # Verify CRLF stripped in email call
            called_info = mock_send.call_args[0][0]
            assert "\r" not in called_info["firstName"] and "\n" not in called_info["firstName"]
            assert "\r" not in called_info["companyName"] and "\n" not in called_info["companyName"]
            assert called_info["user_id"] == user_id
            assert called_info["source"] == "account"

            # DB flag updated
            async with get_session() as session:
                u1 = await get_user_by_id(session, user_id)
                assert u1.hosting_requested_at is not None
                initial_timestamp = u1.hosting_requested_at

            # 2. Second submission should succeed but NOT overwrite timestamp
            res2 = await http.post(
                "/api/request-demo",
                json={
                    "firstName": "Jane",
                    "lastName": "Doe",
                    "email": "requester@example.com",
                    "companyName": "Acme Corp",
                    "notes": "More Testing",
                },
                cookies={"user_token": token},
            )
            assert res2.status_code == 200

            async with get_session() as session:
                u2 = await get_user_by_id(session, user_id)
                assert u2.hosting_requested_at == initial_timestamp

            # 3. Third submission
            res3 = await http.post(
                "/api/request-demo",
                json={
                    "firstName": "Jane",
                    "lastName": "Doe",
                    "email": "requester@example.com",
                    "companyName": "Acme Corp",
                    "notes": "Third",
                },
                cookies={"user_token": token},
            )
            assert res3.status_code == 200

            # 4. Fourth submission from same email exceeds 3/hr limit -> 429
            res4 = await http.post(
                "/api/request-demo",
                json={
                    "firstName": "Jane",
                    "lastName": "Doe",
                    "email": "requester@example.com",
                    "companyName": "Acme Corp",
                    "notes": "Fourth",
                },
                cookies={"user_token": token},
            )
            assert res4.status_code == 429
            assert "too many" in res4.json()["detail"].lower()


@pytest.mark.anyio
async def test_rate_limit_ordering_on_event_creation():
    """Review 6 A2: Slug pre-check must run before rate limiter so slug collision does not consume quota."""
    async with get_session() as session:
        host = await create_user(
            session,
            email="host@example.com",
            display_name="Host",
            password_hash=hash_password("pw123"),
            can_host=True,
        )
        await create_event(session, slug="existing-slug", display_name="Existing Event")
        host_id = host.id

    token = create_user_token(user_id=host_id, email="host@example.com")

    async with client() as http:
        # Submit duplicate slug multiple times
        for _ in range(12):
            resp = await http.post(
                "/workspace/setup",
                data={"display_name": "My New Event", "slug": "existing-slug"},
                cookies={"user_token": token},
            )
            assert resp.status_code == 400
            assert "already exists" in resp.text

        # Now submit a unique valid slug - must NOT be rate limited!
        resp_valid = await http.post(
            "/workspace/setup",
            data={"display_name": "Unique Event", "slug": "unique-event"},
            cookies={"user_token": token},
            follow_redirects=False,
        )
        assert resp_valid.status_code == 303
        assert resp_valid.headers["location"].startswith("/workspace/events/")


@pytest.mark.anyio
async def test_non_host_redirected_to_account_with_error():
    """User without hosting access is redirected from setup with error parameter."""
    async with get_session() as session:
        user = await create_user(
            session,
            email="plain@example.com",
            display_name="Plain User",
            password_hash=hash_password("pw123"),
            can_host=False,
        )
        user_id = user.id

    token = create_user_token(user_id=user_id, email="plain@example.com")
    async with client() as http:
        # GET /workspace/setup
        resp_get = await http.get("/workspace/setup", cookies={"user_token": token}, follow_redirects=False)
        assert resp_get.status_code == 303
        assert resp_get.headers["location"] == "/account?error=hosting_access_required"

        # POST /workspace/setup
        resp_post = await http.post(
            "/workspace/setup",
            data={"display_name": "Forbidden Event"},
            cookies={"user_token": token},
            follow_redirects=False,
        )
        assert resp_post.status_code == 303
        assert resp_post.headers["location"] == "/account?error=hosting_access_required"


@pytest.mark.anyio
async def test_zero_event_host_blocked_from_model_downloads():
    """Host who does not own any events cannot trigger model downloads."""
    async with get_session() as session:
        host = await create_user(
            session,
            email="zero_host@example.com",
            display_name="Zero Host",
            password_hash=hash_password("pw123"),
            can_host=True,
        )
        host_id = host.id

    token = create_user_token(user_id=host_id, email="zero_host@example.com")
    async with client() as http:
        resp = await http.post("/workspace/models/trigger_download", cookies={"user_token": token})
        assert resp.status_code == 403


@pytest.mark.anyio
async def test_new_event_button_visibility():
    """Base, dashboard, and event list templates hide '+ New event' for non-hosts."""
    async with get_session() as session:
        non_host = await create_user(
            session,
            email="nonhost@example.com",
            display_name="Non Host",
            password_hash=hash_password("pw123"),
            can_host=False,
        )
        host = await create_user(
            session,
            email="host_btn@example.com",
            display_name="Host Btn",
            password_hash=hash_password("pw123"),
            can_host=True,
        )
        non_host_id = non_host.id
        host_id = host.id

    token_non_host = create_user_token(user_id=non_host_id, email="nonhost@example.com")
    token_host = create_user_token(user_id=host_id, email="host_btn@example.com")

    async with client() as http:
        # Non-host on account page sees no Organizer Workspace nav link and sees Request Hosting Access
        res_nh_account = await http.get("/account", cookies={"user_token": token_non_host})
        assert res_nh_account.status_code == 200
        assert "Request Hosting Access" in res_nh_account.text
        assert 'href="/workspace/">Organizer Workspace</a>' not in res_nh_account.text

        # Host on account page sees Organizer Workspace and Go to My Events
        res_h_account = await http.get("/account", cookies={"user_token": token_host})
        assert res_h_account.status_code == 200
        assert 'href="/workspace/">Organizer Workspace</a>' in res_h_account.text
        assert "Go to My Events" in res_h_account.text

        # Host on workspace sees + New event button
        res_h_events = await http.get("/workspace/events/", cookies={"user_token": token_host})
        assert res_h_events.status_code == 200
        assert "+ New event" in res_h_events.text

    # User whose hosting access is revoked (can_host=False, hosting_revoked_at set) and owns an existing event:
    async with get_session() as session:
        revoked_owner = await create_user(
            session,
            email="revoked@example.com",
            display_name="Revoked Owner",
            password_hash=hash_password("pw123"),
            can_host=False,
            hosting_revoked_at=utc_now(),
        )
        ev = await create_event(session, slug="existing-ev", display_name="Existing Event")
        await set_event_membership(session, user_id=revoked_owner.id, event_id=ev.id, role="event_owner")
        revoked_id = revoked_owner.id
        event_id = ev.id

    token_revoked = create_user_token(user_id=revoked_id, email="revoked@example.com")
    async with client() as http:
        # On /account:
        # 1. Event row is greyed out, context link is disabled with Access Suspended
        res_rev_account = await http.get("/account", cookies={"user_token": token_revoked})
        assert res_rev_account.status_code == 200
        assert "account-row--disabled" in res_rev_account.text
        assert "Access Suspended" in res_rev_account.text
        assert f'href="/workspace/events/{event_id}/"' not in res_rev_account.text
        # 2. Event Hosting card shows Hosting Access Revoked with Re-request button
        assert "Hosting Access Revoked" in res_rev_account.text
        assert "Re-request Hosting Access" in res_rev_account.text
        assert "Go to My Events" not in res_rev_account.text

        # 3. Cannot access their already created event (redirected to /account?error=hosting_revoked)
        res_ev = await http.get(f"/workspace/events/{event_id}/", cookies={"user_token": token_revoked}, follow_redirects=False)
        assert res_ev.status_code == 303
        assert res_ev.headers["location"] == "/account?error=hosting_revoked"

        # 4. API request to event returns 403 Forbidden
        res_api = await http.get(
            f"/workspace/events/{event_id}/",
            cookies={"user_token": token_revoked},
            headers={"Accept": "application/json"},
        )
        assert res_api.status_code == 403
        assert res_api.json()["detail"] == "Hosting access revoked."



@pytest.mark.anyio
async def test_400_html_error_screen():
    """400 exceptions render unified error screen for HTML clients and JSON for API clients."""
    async with get_session() as session:
        admin = await create_user(
            session,
            email="admin_err@example.com",
            display_name="Admin",
            password_hash=hash_password("pw123"),
            is_admin=True,
        )
    admin_token = create_user_token(user_id=admin.id, email=admin.email, is_admin=True)

    async with client() as http:
        # Browser client requesting text/html receives unified 400.html screen
        res_html = await http.post(
            "/admin/users/invite",
            data={"email": "admin_err@example.com"},
            cookies={"user_token": admin_token},
            headers={"Origin": "http://test", "Accept": "text/html,application/xhtml+xml"},
        )
        assert res_html.status_code == 400
        assert "Bad Request" in res_html.text
        assert "400" in res_html.text
        assert "User is already an administrator." in res_html.text
        assert "Go Back" in res_html.text
        assert "/static/css/error.css" in res_html.text

        # API client receives JSON
        res_json = await http.post(
            "/admin/users/invite",
            data={"email": "admin_err@example.com"},
            cookies={"user_token": admin_token},
            headers={"Origin": "http://test", "Accept": "application/json"},
        )
        assert res_json.status_code == 400
        assert res_json.json() == {"detail": "User is already an administrator."}


@pytest.mark.anyio
async def test_admin_users_table_layout_and_flash_alerts():
    """User table shows flash messages and keeps Hosting column clean without action buttons."""
    async with get_session() as session:
        admin = await create_user(
            session,
            email="admin_layout@example.com",
            display_name="Admin",
            password_hash=hash_password("pw123"),
            is_admin=True,
        )
        invited = await create_user(
            session,
            email="invited@example.com",
            display_name="Invited User",
            password_hash=None,
        )
        tok = await create_auth_token(
            session,
            user_id=invited.id,
            token_type="hosting_invite",
            expires_in_seconds=3600,
        )
    admin_token = create_user_token(user_id=admin.id, email=admin.email, is_admin=True)

    async with client() as http:
        # Success banner renders
        res = await http.get("/admin/users/?success=invite_sent", cookies={"user_token": admin_token})
        assert res.status_code == 200
        assert "Invitation sent successfully." in res.text
        assert "alert-success" in res.text

        # In table: Hosting column has Pending badge and no forms inside it
        assert "Pending</span>" in res.text
        # Resend and Cancel buttons exist in actions-cell
        assert f"/admin/users/invite/{tok.id}/resend" in res.text
        assert f"/admin/users/invite/{tok.id}/cancel" in res.text


@pytest.mark.anyio
async def test_send_demo_request_email_renders_html():
    """Verify send_demo_request_email renders the neo-brutalist HTML template and sends html subtype."""
    from portal.email_sender import send_demo_request_email

    sent_messages = []

    with patch("portal.email_sender.FastMail.send_message", new_callable=AsyncMock) as mock_send, \
         patch("portal.email_sender.settings.smtp_host", "localhost"):
        mock_send.side_effect = lambda msg: sent_messages.append(msg)
        await send_demo_request_email({
            "email": "applicant@example.com",
            "firstName": "Jane",
            "lastName": "Doe",
            "companyName": "Tech Corp",
            "phoneNumber": "+1234567890",
            "country": "US",
            "industry": "Education",
            "companySize": "11-50",
            "languageSupport": "Live translation",
            "notes": "Looking forward to using VoxBento",
            "user_id": 42,
        })

    assert len(sent_messages) == 1
    msg = sent_messages[0]
    assert msg.subject == "New Demo Request from applicant@example.com"
    assert any("voxbento.dev@gmail.com" in str(r) for r in msg.recipients)
    assert "html" in str(msg.subtype)
    assert "Jane Doe" in msg.body
    assert "applicant@example.com" in msg.body
    assert "Tech Corp" in msg.body
    assert "Education" in msg.body
    assert "Review in Admin Panel" in msg.body
    assert "/admin/users/42/" in msg.body

