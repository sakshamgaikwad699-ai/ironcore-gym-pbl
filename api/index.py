"""
Serverless WSGI entry point for Vercel deployment.
Routes incoming serverless HTTP requests to the Flask application instance.
"""

from app import app
