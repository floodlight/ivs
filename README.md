Indigo Virtual Switch
=====================

Introduction
------------

Indigo Virtual Switch (IVS) is a pure OpenFlow virtual switch designed for high
performance and minimal administration. It is built on the [Indigo
platform][1], which provides a common core for many physical and virtual switches,

[1]: http://www.projectfloodlight.org/indigo/

Installation
------------

1. Install required dependencies:
  - Ubuntu 11.10: `sudo apt-get install libnl3-dev pkg-config python-tz`
  - Ubuntu 12.04: `sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev pkg-config python-tz`

2. Compile IVS: `make`

3. Install IVS: `sudo make install DESTDIR=/`

Packaging, including init scripts, is also available for Debian-based
distributions in the `debian` directory.

Usage
-----

You'll need an OpenFlow controller to use IVS. We suggest [Floodlight][2],
which should work out of the box. Follow your controller's instructions
to get it running and note down its IP address.

[2]: http://www.projectfloodlight.org/floodlight/

Now you just need to run the IVS daemon. You'll need to tell it the IP address
of the controller (-c) and the initial set of network interfaces to connect (-i).
Here's an example command line:

```
sudo ivs -c 192.168.1.10 -i eth1 -i eth2
```

IVS will immediately begin communicating with the controller and, depending on
your controller's configuration, forwarding traffic between eth1 and eth2.

`ivs-ctl add-port` and `ivs-ctl del-port` can be used to add and remove ports
at runtime (for example, this is used by hypervisors when a VM is started). See
the `ivs-ctl` man page for more details.

Contributing
------------

Please fork the repository on GitHub and open a pull request.
