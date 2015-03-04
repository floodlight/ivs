Indigo Virtual Switch
=====================

Introduction
------------

Indigo Virtual Switch (IVS) is a pure OpenFlow virtual switch designed for high
performance and minimal administration. It is built on the [Indigo
platform][1], which provides a common core for many physical and virtual switches,

[1]: http://www.projectfloodlight.org/indigo/

This README contains documentation to help you get started using IVS. For full
documentation, see the [IVS][2] pages at Project Floodlight.

[2]: https://docs.projectfloodlight.org/display/indigodocs/Indigo+Virtual+Switch+Documentation

Building IVS
------------

1. Install required dependencies:
  - Ubuntu 14.04: `sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev pkg-config python-tz libpcap-dev`

2. Clone the IVS repository: `git clone --recurse-submodules https://github.com/floodlight/ivs.git`
    - NOTE that if you did not use clone with the "--recursive-submodules" option, you can fix this by running
            `cd ivs && git submodule update --recursive --init`

3. `cd ivs`

4. Compile IVS: `make`

5. The IVS daemon and ivs-ctl utility will be written to
   `targets/ivs/build/gcc-local/bin/ivs` and
   `targets/ivs-ctl/build/gcc-local/bin/ivs-ctl` respectively. They can be run
   directly from the build directory.

Building Debian Packages
------------------------

Packaging, including init scripts, is available for Debian-based
distributions in the `debian` directory. If using git we recommend
git-buildpackage.

The script `build/build-debian-packages.sh` uses Docker to build packages for
Ubuntu 14.04.

Building CentOS/RHEL packages
-----------------------------

Packaging, including init scripts, is available for Red Hat-based
distributions in the `rhel` directory.

The script `build/build-rhel-packages.sh` uses Docker to build packages for
CentOS 7.

Usage
-----

You'll need an OpenFlow controller to use IVS. We suggest [Floodlight][3],
which should work out of the box. Follow your controller's instructions
to get it running and note down its IP address.

[3]: http://www.projectfloodlight.org/floodlight/

The openvswitch kernel module must be loaded: `modprobe openvswitch`.

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

You might be interested in the INTERNALS.md document in this repository which
describes the layout of the source code and includes other details relevant to
developers.
