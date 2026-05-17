# tests/test_auth.py
# Unit tests for Auth module
# Member: Tashi

import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'MONGO_URI': 'mongodb://localhost:27017/phishguard_test',
    })
    with app.test_client() as c:
        yield c


def test_register_page_loads(client):
    """Register page should return 200 OK."""
    r = client.get('/auth/register')
    assert r.status_code == 200


def test_login_page_loads(client):
    """Login page should return 200 OK."""
    r = client.get('/auth/login')
    assert r.status_code == 200


def test_wrong_password_rejected(client):
    """Wrong password should not log in."""
    r = client.post('/auth/login', data={
        'username': 'nonexistent',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert r.status_code == 200


def test_dashboard_requires_login(client):
    """Dashboard should redirect to login if not authenticated."""
    r = client.get('/')
    assert r.status_code == 302


def test_quarantine_requires_login(client):
    """Quarantine page should redirect if not logged in."""
    r = client.get('/quarantine')
    assert r.status_code == 302


def test_admin_requires_login(client):
    """Admin panel should redirect if not logged in."""
    r = client.get('/auth/admin/users')
    assert r.status_code == 302
