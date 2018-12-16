`okta-ice-mvc-flask` is a simple Python/Flask app whose purpose is to demonstrate integrating Okta with your OIDC/OAuth2-compliant MVC application.  It makes use of the [`flask_oidc`](https://github.com/puiterwijk/flask-oidc) library.  This is emphatically **not** a recommendation to use `flask_oidc` in your applications. It's used here for simple purposes of illustration.

This app requires Okta to run. Okta is a free-to-use API service that stores user accounts and makes authentication and authorization simpler. Go create a free Okta developer account before continuing: https://developer.okta.com/signup

To get and run the app locally:

    git clone https://github.com/mdorn/okta-ice-mvc-flask
    cd okta-ice-mvc-flask
    cp .env.example .env. # populate .env with values specific to your Okta org/OIDC app
    python3 -m venv env
    . env/bin/activate
    pip install -r requirements.txt
    FLASK_DEBUG=1 flask run
