struct l2_key {
    unsigned int vlan;
    unsigned int mac_hi;
    unsigned int mac_lo;
};

struct l2_value {
    unsigned int port;
};

struct vlan_key {
    unsigned int vlan;
};

struct vlan_value {
    unsigned int port_bitmap;
};
