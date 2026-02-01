import unittest
from unittest.mock import Mock

from soc2_scanner.collectors import helpers


class CollectorsHelpersTests(unittest.TestCase):
    def test_safe_call_returns_error(self) -> None:
        def _boom() -> None:
            raise helpers.BotoCoreError()

        result, error = helpers.safe_call(_boom)
        self.assertIsNone(result)
        self.assertIsNotNone(error)

    def test_format_error_includes_region(self) -> None:
        message = helpers.format_error("service", "us-east-1", "oops")
        self.assertEqual(message, "service:us-east-1: oops")

    def test_paginate_call_collects_items(self) -> None:
        paginator = Mock()
        paginator.paginate.return_value = [
            {"Items": [{"id": 1}]},
            {"Items": [{"id": 2}, {"id": 3}]},
        ]
        client = Mock()
        client.get_paginator.return_value = paginator

        items, error = helpers.paginate_call(client, "list_things", "Items")
        self.assertEqual([{"id": 1}, {"id": 2}, {"id": 3}], items)
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
