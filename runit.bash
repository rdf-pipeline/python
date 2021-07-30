#! /bin/bash

# Virtualenv:
# https://scoutapm.com/blog/python-flask-tutorial-getting-started-with-flask
# To run (in the virtualenv):
source venv/bin/activate
source /home/dbooth/rdf-pipeline/python/set_env.sh
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_DEBUG=1
export FLASK_RUN_PORT=80
flask run

# To Reimport in interactive shell:
# import importlib
# importlib.reload(app)

