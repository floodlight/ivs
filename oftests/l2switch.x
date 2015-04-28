struct endpoint_key {
    unsigned int vlan;
    unsigned int mac_hi;
    unsigned int mac_lo;
};

struct endpoint_value {
    unsigned int port;
};

struct endpoint_stats {
    /* TODO use 64-bit integers */
    unsigned int packets;
    unsigned int bytes;
};
