# backend/locustfile.py
# Performance/Load testing for PhishGuard
# Member: Aditi (Frontend & DevOps Lead)
#
# HOW TO RUN:
# 1. Make sure app is running: python app.py
# 2. Open new CMD: python -m locust -f locustfile.py --host=http://localhost:5000
# 3. Open browser: http://localhost:8089
# 4. Set: Number of users = 50, Spawn rate = 5
# 5. Click "Start Swarming"

from locust import HttpUser, task, between


class PhishGuardUser(HttpUser):
    # Wait 1-3 seconds between requests (simulates real user behaviour)
    wait_time = between(1, 3)

    def on_start(self):
        """Login before running any tasks."""
        self.client.post('/auth/login', data={
            'username': 'Tashi',
            'password': 'Tashi@1234'
        })

    @task(3)
    def view_dashboard(self):
        """Most common action — view main dashboard."""
        self.client.get('/')

    @task(2)
    def view_analyse_page(self):
        """Second most common — open analyse page."""
        self.client.get('/analyse')

    @task(1)
    def analyse_phishing_email(self):
        """Analyse a phishing email — tests full pipeline."""
        self.client.post('/analyse', data={
            'email_text': (
                'URGENT your account will be suspended within 24 hours '
                'verify now at http://secure-bank-verification-login.com '
                'enter your bank account details and password immediately'
            )
        })

    @task(1)
    def view_login_page(self):
        """View login page — tests auth endpoint."""
        self.client.get('/auth/login')