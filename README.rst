.. image:: http://nikolaskama.me/content/images/2017/02/kickthemout_small.png

KickThemOut
============

`KickThemOut <https://nikolaskama.me/kickthemoutproject/>`_ - **Kick Devices Off Your Network**

A tool to kick devices out of your network and enjoy all the bandwidth for yourself.
It allows you to select specific or all devices and ARP spoofs them off your local area network.

Compatible with Python 2.6 & 2.7.

Authors: `Nikolaos Kamarinakis <mailto:nikolaskam@gmail.com>`_  & `David Schütz <mailto:xdavid@protonmail.com>`_.

.. image:: https://travis-ci.org/k4m4/kickthemout.svg?branch=master
    :target: https://travis-ci.org/k4m4/kickthemout
.. image:: https://img.shields.io/badge/license-MIT-blue.svg
    :target: https://github.com/k4m4/kickthemout/blob/master/LICENSE
.. image:: https://img.shields.io/badge/made%20with-%3C3-red.svg
    :target: https://nikolaskama.me/kickthemoutproject
.. image:: https://img.shields.io/github/stars/k4m4/kickthemout.svg
    :target: https://github.com/k4m4/kickthemout/stargazers
    
-------------

Debian Installation
----------------------

You can download KickThemOut by cloning the `Git Repo <https://github.com/k4m4/kickthemout>`_ and simply installing its requirements::

    $ sudo apt-get update && sudo apt-get install nmap

    $ git clone https://github.com/k4m4/kickthemout.git
    
    $ cd kickthemout/

    $ sudo -H pip install --upgrade pip
    
    $ sudo -H python -m pip install -r requirements.txt
    
    $ sudo python kickthemout.py

MacOS Installation
----------------------

If you would like to install KickThemOut on a Mac, please run the following::

    $ sudo -H pip install --upgrade pip
    
    $ sudo -H pip install pcapy
    
    $ brew update

    $ brew install --with-python libdnet nmap

**Keep in mind** that you might be asked to run some commands after executing the previous step. Moving on::

    $ git clone https://github.com/k4m4/kickthemout.git

    $ cd kickthemout/

    $ sudo -H pip install -r requirements.txt
    
    $ sudo python kickthemout.py

**NOTE**: You need to have `Homebrew <http://brew.sh/>`_ installed before running the Mac OS installation.

Arch Installation
----------------------

You can download KickThemOut on an Arch based system by executing the following::

    $ yaourt -S kickthemout-git
    
    $ sudo kickthemout

Demo
-----

Here's a short demo:

.. image:: https://nikolaskama.me/content/images/2017/01/kickthemout_asciinema.png
   :target: https://asciinema.org/a/98200?autoplay=1&loop=1

(For more demos click `here <https://asciinema.org/~k4m4>`_.)

Developers
-----------

* Nikolaos Kamarinakis - `@nikolaskama <https://twitter.com/nikolaskama>`_
* David Schütz - `@xdavidhu <https://twitter.com/xdavidhu>`_

Disclaimer
-----------

KickThemOut is provided as is under the MIT Licence (as stated below). 
It is built for educational purposes only. If you choose to use it otherwise, the developers will not be held responsible. 
In brief, do not use it with evil intent.

License
--------

Copyright (c) 2017 by `Nikolaos Kamarinakis <mailto:nikolaskam@gmail.com>`_ & `David Schütz <mailto:xdavid@protonmail.com>`_. Some rights reserved.

KickThemOut is under the terms of the `MIT License <https://www.tldrlegal.com/l/mit>`_, following all clarifications stated in the `license file <https://raw.githubusercontent.com/k4m4/kickthemout/master/LICENSE>`_.


For more information head over to the `official project page <https://nikolaskama.me/kickthemoutproject/>`_.
You can also go ahead and email me anytime at **nikolaskam{at}gmail{dot}com** or David at **xdavid{at}protonmail{dot}com**.
