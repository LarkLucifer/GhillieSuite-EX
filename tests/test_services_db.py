import unittest

from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Host, Service, Endpoint
from ghilliesuite_ex.utils.scope import load_scope


class TestServicesDB(unittest.IsolatedAsyncioTestCase):
    async def test_insert_and_get_services(self) -> None:
        async with StateDB(":memory:", target="example.com") as db:
            host_id = await db.insert_host(Host(domain="example.com"))
            svc = Service(host_id=host_id, port=80, proto="tcp", service="http", source_tool="naabu")
            await db.insert_service(svc)
            rows = await db.get_services(host_id=host_id)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].port, 80)
            self.assertEqual(rows[0].proto, "tcp")

    async def test_update_endpoint_params(self) -> None:
        async with StateDB(":memory:", target="example.com") as db:
            await db.insert_endpoint(Endpoint(url="https://example.com/api", params="a"))
            await db.update_endpoint_params("https://example.com/api", "b,c")
            eps = await db.get_endpoints()
            self.assertEqual(eps[0].params, "a,b,c")

    async def test_get_hosts_uses_strict_scope_rules(self) -> None:
        async with StateDB(":memory:", target="example.com") as db:
            await db.insert_host(Host(domain="example.com"))
            await db.insert_host(Host(domain="api.example.com"))

            exact_hosts = await db.get_hosts(scope_domains=load_scope("example.com"))
            wildcard_hosts = await db.get_hosts(scope_domains=load_scope("*.example.com"))

            self.assertEqual([host.domain for host in exact_hosts], ["example.com"])
            self.assertEqual([host.domain for host in wildcard_hosts], ["api.example.com"])


if __name__ == "__main__":
    unittest.main()
