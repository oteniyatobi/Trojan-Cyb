import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import admin_store
from api import app

HEADERS = {"Authorization": "Bearer admin-token"}
ORG = "11111111-1111-1111-1111-111111111111"
USER = "22222222-2222-2222-2222-222222222222"
ADMIN = "33333333-3333-3333-3333-333333333333"


class AdminEndpointTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_requires_sign_in(self):
        self.assertEqual(self.client.get("/v1/admin/organizations").status_code, 401)

    @patch("api.admin_store.platform_admin_id", return_value=None)
    def test_rejects_non_platform_admin(self, _admin):
        response = self.client.get("/v1/admin/organizations", headers=HEADERS)

        self.assertEqual(response.status_code, 403)

    @patch("api.admin_store.list_organizations", return_value=[{"id": ORG}])
    @patch("api.admin_store.platform_admin_id", return_value=ADMIN)
    def test_lists_organizations(self, _admin, _list):
        response = self.client.get("/v1/admin/organizations", headers=HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["organizations"], [{"id": ORG}])

    @patch("api.admin_store.create_organization", return_value={"id": ORG, "name": "Acme"})
    @patch("api.admin_store.platform_admin_id", return_value=ADMIN)
    def test_creates_organization(self, _admin, create):
        response = self.client.post(
            "/v1/admin/organizations",
            json={"name": "Acme", "admin_email": "a@acme.test"},
            headers=HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        create.assert_called_once_with(ADMIN, "Acme", "a@acme.test")

    @patch("api.admin_store.create_organization",
           side_effect=admin_store.AdminError("No TROJAN account uses that email.", 404))
    @patch("api.admin_store.platform_admin_id", return_value=ADMIN)
    def test_unknown_admin_email_returns_404(self, _admin, _create):
        response = self.client.post(
            "/v1/admin/organizations", json={"name": "Acme", "admin_email": "x@y.test"}, headers=HEADERS,
        )

        self.assertEqual(response.status_code, 404)

    @patch("api.admin_store.set_member_role")
    @patch("api.admin_store.platform_admin_id", return_value=ADMIN)
    def test_changes_member_role(self, _admin, set_role):
        response = self.client.patch(
            f"/v1/admin/organizations/{ORG}/members/{USER}", json={"role": "viewer"}, headers=HEADERS,
        )

        self.assertEqual(response.status_code, 200)
        set_role.assert_called_once_with(ADMIN, ORG, USER, "viewer")

    @patch("api.admin_store.create_ingest_key", return_value={"id": "k1", "key": "raw"})
    @patch("api.admin_store.platform_admin_id", return_value=ADMIN)
    def test_creates_key(self, _admin, create):
        response = self.client.post(f"/v1/admin/organizations/{ORG}/keys", json={"label": "wazuh"}, headers=HEADERS)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["key"], "raw")
        create.assert_called_once_with(ADMIN, ORG, "wazuh")

    @patch("api.admin_store.platform_admin_id", return_value=ADMIN)
    def test_bad_key_id_returns_404(self, _admin):
        response = self.client.post("/v1/admin/keys/nope/revoke", headers=HEADERS)

        self.assertEqual(response.status_code, 404)


class AdminStoreTests(unittest.TestCase):
    @patch("admin_store.get_supabase_client")
    def test_key_is_stored_as_hash_only(self, get_client):
        client = MagicMock()
        get_client.return_value = client
        client.table.return_value.select.return_value.eq.return_value.execute.return_value = SimpleNamespace(
            data=[{"id": ORG}],
        )
        client.table.return_value.insert.return_value.execute.return_value = SimpleNamespace(
            data=[{"id": "k1", "label": "wazuh", "created_at": "now"}],
        )

        created = admin_store.create_ingest_key(ADMIN, ORG, "wazuh")

        inserted = client.table.return_value.insert.call_args_list[0].args[0]
        self.assertEqual(inserted["key_hash"], hashlib.sha256(created["key"].encode()).hexdigest())
        self.assertNotIn(created["key"], str(inserted))

    def test_rejects_unknown_role(self):
        with self.assertRaises(admin_store.AdminError):
            admin_store.set_member_role(ADMIN, ORG, USER, "owner")


if __name__ == "__main__":
    unittest.main()
