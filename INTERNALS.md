Source Code Layout
------------------

The IVS repository uses the same source code module infrastructure and build
system as the Indigo project (which is included as a submodule under `indigo`).
Here's an (abridged) source code tree:

 - build: Convenience scripts for building and running IVS.
 - debian: Debian packaging.
 - indigo: Submodule linking to floodlight/indigo.
 - modules
   - flowtable: Hash-based flowtable implementation.
   - OVSDriver: Implementation of Indigo Forwarding/PortManager interfaces
     using the openvswitch kernel module.
     - module
       - inc: OVSDriver public headers.
       - src: OVSDriver implementation.
 - openvswitch: Header files for the openvswitch netlink interface.
 - targets
   - ivs: Switch daemon.
   - ivs-ctl: Utility to add/remove ports from the switch.

The OVSDriver module is the main component of the project and has several submodules:

 - bh.c: "Bottom-halves" - queue of requests from upcall threads to the main
   thread.
 - fwd.c: Implements the Indigo forwarding interface.
 - kflow.c: Manages kernel flows (installation, invalidation, expiration).
 - ovs_driver.c: Initialization/cleanup.
 - translate_actions.c: Translation from OpenFlow matches and actions to
   openvswitch actions.
 - upcall.c: Handles upcalls from the openvswitch module.
 - vport.c: Implements the Indigo port manager interface.

The ovs_driver_int.h file defines the internal interfaces between these
submodules.

Upcall Processing
-----------------

"Upcalls" are messages from the openvswitch kernel module to userspace sent
when the kernel does not have an exact-match flow for a packet. The main
function of IVS is to handle these upcalls efficiently.

The IVS daemon spawns several threads (default 4) to handle upcalls. Each
thread is assigned a set of ports. One Netlink socket is used per port for
isolation. An upcall thread spins forever around epoll_wait(), waiting for new
messages from its assigned ports.

When an upcall thread is woken from epoll_wait() it will read messages from the
kernel in large batches to reduce the number of user/kernel transitions. For
each message, it dispatches to the relevant handler depending on the type of
upcall. For now we'll assume the upcalls are "misses", meaning there was no
matching flow in the kernel flowtable.

When handling a miss, the upcall thread uses the flow key sent by the kernel to
do a lookup in the userspace flowtable. If no flow was found the thread uses
the BH queue to request a packet-in. Otherwise, it translates the OpenFlow
actions into openvswitch datapath actions and sends the packet up to the
datapath with an "execute" message.

For long-lived flows we want to avoid repeated round-trips to userspace to make
forwarding decisions. Each upcall thread maintains a Bloom filter which it uses
to (probabilistically) determine if it's seen a given flow key before. If so,
it uses the BH queue to request a new kernel flow from the kflow subsystem.
Installing a kernel flow is a synchronization bottleneck in the openvswitch
kernel module so we want to avoid it for very short flows. This heuristic will
continue to be tuned in the future.
