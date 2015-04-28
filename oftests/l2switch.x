struct l2_key {
    unsigned int vlan;
    unsigned int mac_hi;
    unsigned int mac_lo;
};

struct l2_value {
    unsigned int port;
};

struct l2_stats {
    /* TODO use 64-bit integers */
    unsigned int packets;
    unsigned int bytes;
};

struct vlan_key {
    unsigned int vlan;
};

struct vlan_value {
    unsigned int port_bitmap;
};
