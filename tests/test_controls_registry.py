from soc2_scanner.controls import CONTROL_REGISTRY


def test_control_registry_contains_core_controls() -> None:
    assert {"CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8"}.issubset(
        set(CONTROL_REGISTRY.keys())
    )
