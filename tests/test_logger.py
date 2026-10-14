from src.capture.logger import in_scope, is_api_request


def test_exact_domain_is_in_scope():
    assert in_scope("lab.example.test", "lab.example.test")


def test_subdomain_is_in_scope():
    assert in_scope("api.lab.example.test", "lab.example.test")


def test_unrelated_domain_is_out_of_scope():
    assert not in_scope("other.example.test", "lab.example.test")


def test_domain_suffix_attack_is_not_in_scope():
    assert not in_scope("lab.example.test.attacker.invalid", "lab.example.test")


def test_api_path_is_included():
    assert is_api_request("https://lab.example.test/api/students/105/profile")


def test_static_asset_is_excluded():
    assert not is_api_request("https://lab.example.test/api/images/profile.png")


def test_non_api_path_is_excluded():
    assert not is_api_request("https://lab.example.test/students/105/profile")
