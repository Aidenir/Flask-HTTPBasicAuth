"""
Flask-HTTPAuth
--------------

Basic and Digest HTTP authentication for Flask routes.
"""
from setuptools import setup


setup(
    name='Flask-HTTPBasicAuth',
    version='1.0.0',
    url='http://github.com/Aidenir/flask-httpbasicauth/',
    license='MIT',
    author='Viktor Hansson',
    author_email='viktor.hansson@me.com',
    description='Basic authentication for Flask routes',
    long_description=__doc__,
    py_modules=['flask_httpbasicauth'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask'
    ],
    test_suite = "test_httpauth",
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
