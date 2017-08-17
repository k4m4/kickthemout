![KickThemOut Logo](http://nikolaskama.me/content/images/2017/02/kickthemout_small.png)

# KickThemOut

> [KickThemOut](https://nikolaskama.me/kickthemoutproject) - **Kick Devices Off Your Network**

A tool to kick devices out of your network and enjoy all the bandwidth for yourself.
It allows you to select specific or all devices and ARP spoofs them off your local area network.

- Compatible with Python **2.6** & **2.7**. 

- *Not* compatible with Windows.

Authors: [Nikolaos Kamarinakis](mailto:nikolaskam@gmail.com) & [David Schütz](mailto:xdavid@protonmail.com).

[![Build Badge](https://travis-ci.org/k4m4/kickthemout.svg?branch=master)](https://travis-ci.org/k4m4/kickthemout)
[![License Badge](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/k4m4/kickthemout/blob/master/LICENSE)
[![Made with <3 Badge](https://img.shields.io/badge/made%20with-%3C3-red.svg)](https://nikolaskama.me/kickthemoutproject)
[![](https://img.shields.io/github/stars/k4m4/kickthemout.svg)](https://github.com/k4m4/kickthemout/stargazers)

TODO:
------

- [x] Fix **README.rst —> README.md**
- [ ] Fix **ERROR —> Error**
- [ ] Add **Error Codes** (e.g. Error 21, IOError: [Errno 6] Device not configured)
- [ ] Add **How it Works** to README
- [ ] Add **DNS Poisoning Attack** (test)
- [ ] Add **Deauth Attack**
- [x] Implement **ParseOpt**
- [ ] Add **loading animation** (like in msfconsole)
- [x] Fix **^C error when scanning** (doesn’t quit)
- [x] Fix **^C^C** error —> ‘kickthemout> ^C^C’ (must enter ^C twice to quite)
- [ ] Implement **clock** (like in onioff)
- [ ] Disallow **kicking gateway out** (only in kickalloff())
- [x] Add **select attack method** option
- [x] Add elif statements for cases where there’s **only one argument** (e.g. ❯❯❯ sudo python kickthemout.py --attack arp)
- [x] Add optparse option for **number of packets** per second (—packets, -p)
- [ ] Turn **select attack method** into function 
- [ ] Fix: If IP address in scan is too short, the **tab appears messed up**
- [ ] **Start from [0]** in all options (not just when selecting target)
- [x] Implement: **`kickONEOff/{attackVector} Spoofing selected…`**
- [ ] Handle **EOFError** (when doing ^D instead of ^C)
- [ ] Add **FAQ** to README
- [ ] Add **Requirements Error Guide** to README (alternative methods to try and solve error)
- [ ] Create **setup.py** (or bash script)
- [ ] Add **—scan option** (for simple nmap scan) (MAYBE)
- [x] **Remove ‘%’** in the end of  ❯❯❯ sudo python kickthemout.py -h
- [ ] Add **USAGE** to README
- [ ] **Change text var** to actual text in scanningAnimation(text) function
- [x] Implement camelcase to all variable names
- [ ] Migrate all **double quotes to single quotes**
- [ ] Add **keyboard exception** to scanningAnimation(text)
- [ ] Create **man page**
    
-------------

Debian Installation
----------------------

You can download KickThemOut by cloning the [Git Repo](https://github.com/k4m4/kickthemout) and simply installing its requirements:

```
~ ❯❯❯ sudo apt-get update && sudo apt-get install nmap

~ ❯❯❯ git clone https://github.com/k4m4/kickthemout.git

~ ❯❯❯ cd kickthemout/

~/kickthemout ❯❯❯ sudo python -m pip install -r requirements.txt

~/kickthemout ❯❯❯ sudo python kickthemout.py
```


MacOS Installation
-------------------

If you would like to install KickThemOut on a Mac, please run the following:

```
~ ❯❯❯ sudo python -m pip install pcapy

~ ❯❯❯ brew install libdnet nmap

~ ❯❯❯ git clone https://github.com/k4m4/kickthemout.git

~ ❯❯❯ cd kickthemout/

~/kickthemout ❯❯❯ sudo python -m pip install -r requirements.txt

~/kickthemout ❯❯❯ sudo python kickthemout.py
```

**NOTE**: You need to have [Homebrew](http://brew.sh/) installed before running the Mac OS installation. 

Also, **keep in mind** that you might be asked to run some commands after executing the last step.


Arch Installation
------------------

You can download KickThemOut on an Arch based system by executing the following:

```
~ ❯❯❯ git clone https://github.com/k4m4/kickthemout.git

~ ❯❯❯ cd kickthemout/

~ ❯❯❯ sudo -H python2 -m pip install -r requirements.txt

~/kickthemout ❯❯❯ sudo python2 kickthemout.py
```


Demo
-----

Here's a short demo:

[![Asciinema Demo](https://nikolaskama.me/content/images/2017/01/kickthemout_asciinema.png)](https://asciinema.org/a/98200?autoplay=1&loop=1)

(For more demos click [here](https://asciinema.org/~k4m4))


How it works
-------------
*TODO*


FAQ
----
*TODO*


Developers
-----------

* Nikolaos Kamarinakis - [@nikolaskama](https://twitter.com/nikolaskama)
* David Schütz - [@xdavidhu](https://twitter.com/xdavidhu)


Disclaimer
-----------

KickThemOut is provided as is under the MIT Licence (as stated below). 
It is built for educational purposes *only*. If you choose to use it otherwise, the developers will not be held responsible. Please, do not use it with evil intent.


License
--------

Copyright (c) 2017 by [Nikolaos Kamarinakis](mailto:nikolaskam@gmail.com) & [David Schütz](mailto:xdavid@protonmail.com). Some rights reserved.

KickThemOut is under the terms of the [MIT License](https://www.tldrlegal.com/l/mit), following all clarifications stated in the [license file](https://raw.githubusercontent.com/k4m4/kickthemout/master/LICENSE).


For more information head over to the [official project page](https://nikolaskama.me/kickthemoutproject).
You can also go ahead and email me anytime at **nikolaskam{at}gmail{dot}com** or David at **xdavid{at}protonmail{dot}com**.
