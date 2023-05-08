- In the case of error when using command:
  ```bash=
  sudo a2enmod wsgi
  ```
  Run the following command, and try again::
  ```bash=
  sudo apt-get purge libapache2-mod-wsgi libapache2-mod-wsgi-py3
  sudo apt-get install libapache2-mod-wsgi libapache2-mod-wsgi-py3
  ```