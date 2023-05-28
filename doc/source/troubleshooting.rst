===============
Troubleshooting
===============

**OpenStack components run in systemd but can not access Horizon dashboard.**

* If you are using **Anaconda** to run OpenStack cloud, update the `/etc/apache2/apache2.conf`

  .. code-block:: apache

    # other configurations...
    WSGIPythonHome /home/<user>/anaconda3/envs/<env_name>

    <Directory />
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Directory /home/<user>/anaconda3>
        AllowOverride All
        Require all granted
    </Directory>

    <Directory /usr/share>
        AllowOverride All
        Require all granted
    </Directory>

    <Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

* Then **restart** the **apache2** service

  .. code-block:: bash

    sudo systemctl restart apache2

**Libvirt not work with Anaconda.**

* If you are using **Anaconda** to run OpenStack cloud, you need to install **libvirt** with `pip`.

  .. code-block:: bash

    pip install libvirt-python==6.1.0

**Can not install uwsgi package with Anaconda**

* Run the below command to install `uwsgi` package in Anaconda.

  .. code-block:: bash

    conda install -c conda-forge uwsgi




