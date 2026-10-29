"""
WSGI entry point for production deployments such as PythonAnywhere.
Exposes Flask WSGI application object as `application`.
"""

from app import app as application

if __name__ == "__main__":
    application.run()
