import pytest
from securiscan.core.config import AuthConfig, ProxyConfig, ScanLevel, AuthType, HttpUrl

class TestAuthConfig:
    """Tests for the AuthConfig class."""

    def test_auth_config_initialization(self):
        """Test that AuthConfig initializes correctly."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            credentials={"username": "testuser", "password": "testpass"},
        )

        assert config.auth_type == AuthType.BASIC
        assert config.credentials == {"username": "testuser", "password": "testpass"}

    def test_auth_config_default_values(self):
        """Test that AuthConfig uses default values correctly."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            credentials={"username": "testuser", "password": "testpass"},
        )

        assert config.auth_type == AuthType.BASIC
        assert config.credentials == {"username": "testuser", "password": "testpass"}

    def test_auth_config_dict_method(self):
        """Test that the model_dump method returns a dictionary representation of the config."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            credentials={"username": "testuser", "password": "testpass"},
        )

        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert config_dict["auth_type"] == AuthType.BASIC.value
        assert config_dict["credentials"] == {"username": "testuser", "password": "testpass"}


class TestProxyConfig:
    """Tests for the ProxyConfig class."""

    def test_proxy_config_initialization(self):
        """Test that ProxyConfig initializes correctly."""
        config = ProxyConfig(
            proxy_url="http://localhost:8080",
            proxy_auth={"username": "proxyuser", "password": "proxypass"},
        )

        assert str(config.proxy_url) == "http://localhost:8080/"
        assert config.proxy_auth == {"username": "proxyuser", "password": "proxypass"}

    def test_proxy_config_default_values(self):
        """Test that ProxyConfig uses default values correctly."""
        config = ProxyConfig(
            proxy_url="http://localhost:8080",
        )

        assert str(config.proxy_url) == "http://localhost:8080/"
        assert config.proxy_auth is None

    def test_proxy_config_dict_method(self):
        """Test that the model_dump method returns a dictionary representation of the config."""
        config = ProxyConfig(
            proxy_url="http://localhost:8080",
            proxy_auth={"username": "proxyuser", "password": "proxypass"},
        )

        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert config_dict["proxy_url"] == "http://localhost:8080/"
        assert config_dict["proxy_auth"] == {"username": "proxyuser", "password": "proxypass"}

class TestScanLevel:
    """Tests for the ScanLevel enum."""

    def test_scan_level_values(self):
        """Test that ScanLevel has the expected values."""
        assert ScanLevel.LIGHT.value == "light"
        assert ScanLevel.STANDARD.value == "standard"
        assert ScanLevel.DEEP.value == "deep"
        assert ScanLevel.FULL.value == "full"


class TestAuthType:
    """Tests for the AuthType enum."""

    def test_auth_type_values(self):
        """Test that AuthType has the expected values."""
        assert AuthType.BASIC.value == "basic"
        assert AuthType.BEARER_TOKEN.value == "bearer_token"
        assert AuthType.API_KEY.value == "api_key"
