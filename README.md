# WebAuthn module
This is a brief guide to install the WebAuthn module, the guide will be more detailed in the future.

This module is mainly intended to be used for SATOSA but can be connected to other systems as well.

## System Requirements
- Apache2 / Nginx + HTTPS
- libapache2-mod-wsgi-py3
- MySQL server
- Python3.6

## Python3 Libraries
- flask
- flask-login
- cbor2
- mysql-connector-python
- pyjwkest



## Installation
Installation is described using Apache2 and Ubuntu. 

Clone this repository and then properly fill out the `config.yaml` file. The parameters are described in the example file that is provided.

After you download the system requirements and libraries, you need to add the module to the Apache sites-enabled.

Then you need to create the database and tables that the module will use. For this purpose, you can use the `create_db.py` script that does the job for you if you provided correct database parameters in the `config.yaml` file.

The installation is finished.

## Apache2 sites-enabled example
```
WSGIPythonPath /var/webauthn-module/py_webauthn/flask_demo/venv/:/var/webauthn-module/py_webauthn/flask_demo/venv/lib/python3.5/site-packages
<IfModule mod_ssl.c>
<VirtualHost *:443>
        WSGIScriptAlias / /var/webauthn-module/app.wsgi
        <Directory /var/webauthn-module>
	  Require all granted
        </Directory>
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
ServerName ip-78-128-251-141.flt.cloud.muni.cz
SSLCertificateFile /etc/letsencrypt/live/ip-78-128-251-141.flt.cloud.muni.cz/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/ip-78-128-251-141.flt.cloud.muni.cz/privkey.pem
Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
</IfModule>
```

## License
Will be added
