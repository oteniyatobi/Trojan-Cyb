import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import admin_store
from api import app

ORG = "11111111-1111-1111-1111-111111111111"
USER = "44444444-4444-4444-4444-444444444444"


def service_with(existing_member=False):
    client = MagicMock()
    table = client.table.return_value
    table.select.return_value.eq.return_value.limit.return_value.execute.return_value = SimpleNamespace(
        data=[{"id": ORG}],
    )
    table.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value = (
        SimpleNamespace(data=[{"role": "viewer"}] if existing_member else [])
    )
    return client


class AddMemberTests(unittest.TestCase):
    @patch("admin_store._audit")
    @patch("admin_store._invite")
    @patch("admin_store._user_id_for_email", return_value=USER)
    @patch("admin_store.get_supabase_client")
    def test_existing_account_is_added_without_invite(self, get_client, _lookup, invite, _audit):
        get_client.return_value = service_with()

        result = admin_store.add_member("actor", ORG, " Person@Example.com ", "org_admin")

        self.assertEqual(result, {"user_id": USER, "email": "person@example.com", "role": "org_admin", "invited": False})
        invite.assert_not_called()
        row = get_client.return_value.table.return_value.insert.call_args.args[0]
        self.assertEqual(row, {"organization_id": ORG, "user_id": USER, "role": "org_admin"})

    @patch("admin_store._audit")
    @patch("admin_store._invite", return_value=USER)
    @patch("admin_store._user_id_for_email", return_value=None)
    @patch("admin_store.get_supabase_client")
    def test_new_email_gets_an_invite(self, get_client, _lookup, invite, _audit):
        get_client.return_value = service_with()

        result = admin_store.add_member("actor", ORG, "new@example.com", "viewer")

        self.assertTrue(result["invited"])
        invite.assert_called_once_with("new@example.com")

    @patch("admin_store._user_id_for_email", return_value=USER)
    @patch("admin_store.get_supabase_client")
    def test_existing_member_is_rejected(self, get_client, _lookup):
        get_client.return_value = service_with(existing_member=True)
        with self.assertRaises(admin_store.AdminError) as raised:
            admin_store.add_member("actor", ORG, "person@example.com", "viewer")
        self.assertEqual(raised.exception.status, 409)

    def test_bad_email_and_role_are_rejected(self):
        for email, role in (("not-an-email", "viewer"), ("a@b.com", "owner")):
            with self.assertRaises(admin_store.AdminError):
                admin_store.add_member("actor", ORG, email, role)


class MemberRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.auth = {"Authorization": "Bearer token"}

    def test_members_need_sign_in(self):
        self.assertEqual(self.client.get(f"/v1/organizations/{ORG}/members").status_code, 401)

    @patch("admin_store.add_member")
    @patch("admin_store.organization_role", return_value=(USER, "analyst"))
    def test_only_org_admins_can_add(self, _role, add):
        response = self.client.post(
            f"/v1/organizations/{ORG}/members", json={"email": "a@b.com"}, headers=self.auth,
        )
        self.assertEqual(response.status_code, 403)
        add.assert_not_called()

    @patch("admin_store.add_member", return_value={"invited": True})
    @patch("admin_store.organization_role", return_value=(USER, "org_admin"))
    def test_org_admin_can_add(self, _role, add):
        response = self.client.post(
            f"/v1/organizations/{ORG}/members",
            json={"email": "a@b.com", "role": "analyst"},
            headers=self.auth,
        )
        self.assertEqual(response.status_code, 201)
        add.assert_called_once_with(USER, ORG, "a@b.com", "analyst")

    @patch("admin_store.add_member", return_value={"invited": False})
    @patch("admin_store.organization_role", return_value=(USER, "platform_admin"))
    def test_trojan_admin_can_add_to_any_org(self, _role, add):
        response = self.client.post(
            f"/v1/organizations/{ORG}/members", json={"email": "a@b.com"}, headers=self.auth,
        )
        self.assertEqual(response.status_code, 201)
        add.assert_called_once_with(USER, ORG, "a@b.com", "viewer")

    @patch("admin_store.organization_role", side_effect=admin_store.AdminError("nope", 403))
    def test_non_members_cannot_list(self, _role):
        response = self.client.get(f"/v1/organizations/{ORG}/members", headers=self.auth)
        self.assertEqual(response.status_code, 403)

    @patch("admin_store.platform_admin_id", return_value=None)
    def test_admin_route_needs_platform_admin(self, _):
        response = self.client.post(
            f"/v1/admin/organizations/{ORG}/members", json={"email": "a@b.com"}, headers=self.auth,
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
