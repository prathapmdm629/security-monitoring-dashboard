import os
import tempfile
import pytest
from app import app as flask_app

@pytest.fixture()
def client():
    db = tempfile.NamedTemporaryFile(delete=False)
    db.close()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, DATABASE=db.name, SECRET_KEY='test-secret')
    with flask_app.app_context():
        from app import init_db
        init_db()
    with flask_app.test_client() as test_client:
        yield test_client
    os.unlink(db.name)

def login(client, username='admin', password='Admin@123'):
    return client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

def test_application_starts_and_seeds_alerts(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert client.get('/alerts').status_code == 302
    assert 'WATCHTOWER' in response.get_data(as_text=True)

def test_login_success_and_dashboard(client):
    response = login(client)
    assert response.status_code == 200
    assert 'Operations overview' in response.get_data(as_text=True)
    assert client.get('/alerts').status_code == 200
    assert 'Multiple Failed Login Attempts' in client.get('/alerts').get_data(as_text=True)

def test_login_failure(client):
    response = client.post('/login', data={'username': 'admin', 'password': 'wrong'}, follow_redirects=True)
    assert 'Invalid username or password' in response.get_data(as_text=True)

def test_logout(client):
    login(client)
    response = client.post('/logout', follow_redirects=True)
    assert 'SECURE ACCESS' in response.get_data(as_text=True)

def test_role_based_access(client):
    login(client, 'viewer', 'Viewer@123')
    assert client.get('/analysts').status_code == 403
    assert client.post('/alerts/1/status', data={'status': 'Closed'}).status_code == 403
    assert client.get('/alerts').status_code == 200

def test_alert_detail_and_status_update(client):
    login(client, 'analyst', 'Analyst@123')
    assert client.get('/alerts/1').status_code == 200
    response = client.post('/alerts/1/status', data={'status': 'Investigating'}, follow_redirects=True)
    assert response.status_code == 200
    assert 'Investigating' in response.get_data(as_text=True)

def test_incident_creation(client):
    login(client, 'analyst', 'Analyst@123')
    response = client.post('/incidents/create', data={'title': 'Correlated endpoint review', 'description': 'Review related telemetry.', 'severity': 'High'}, follow_redirects=True)
    assert response.status_code == 200
    assert 'Correlated endpoint review' in response.get_data(as_text=True)

def test_investigation_note_and_activity(client):
    login(client, 'analyst', 'Analyst@123')
    response = client.post('/alerts/1/notes', data={'note': 'Observed repeated authentication failures.'}, follow_redirects=True)
    assert response.status_code == 200
    assert 'Observed repeated authentication failures.' in response.get_data(as_text=True)
    assert client.get('/activity').status_code == 200
