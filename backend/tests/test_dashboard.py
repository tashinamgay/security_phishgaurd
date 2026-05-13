# tests/test_dashboard.py
# Unit tests for Dashboard module
# Member: Aditi

import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        MONGO_URI='mongodb://localhost:27017/phishguard_test'
    )
    with app.test_client() as c:
        yield c


def test_dashboard_redirects_to_login(client):
    assert client.get('/').status_code == 302


def test_analyse_redirects_to_login(client):
    assert client.get('/analyse').status_code == 302


def test_quarantine_redirects_to_login(client):
    assert client.get('/quarantine').status_code == 302


def test_security_panel_redirects_to_login(client):
    assert client.get('/admin/security').status_code == 302


def test_ml_train_redirects_to_login(client):
    assert client.get('/ml-train').status_code == 302


def test_export_csv_redirects_to_login(client):
    assert client.get('/export/csv').status_code == 302
