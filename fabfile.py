from fabric.api import *
import os

HOME_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.join(HOME_DIR, 'secrets')

def test(verbose=None):
    """
    Run tests for this project.
    """
    with lcd(HOME_DIR):
        with settings(hide('running', 'aborts', 'warnings'), warn_only=True):
            local("nosetests --nocapture%s" % (" --verbose" if verbose == "true" else "", ))
