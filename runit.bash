#! /bin/bash

# Virtualenv:
# https://scoutapm.com/blog/python-flask-tutorial-getting-started-with-flask
# To run (in the virtualenv):
source bin/activate
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_DEBUG=1
flask run

