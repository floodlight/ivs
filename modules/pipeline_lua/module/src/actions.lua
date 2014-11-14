local ffi = require("ffi")
local C = ffi.C
local context = context

ffi.cdef[[
typedef struct of_ipv6_s {
   uint8_t addr[16];
} of_ipv6_t;

/* Output */

void action_controller(struct action_context *ctx, uint64_t userdata);
void action_output(struct action_context *ctx, uint32_t port_no);
void action_output_local(struct action_context *ctx);
void action_output_in_port(struct action_context *ctx);

/* Ethernet */

void action_set_eth_dst_scalar(struct action_context *ctx, uint32_t mac_lo, uint16_t mac_hi);
void action_set_eth_src_scalar(struct action_context *ctx, uint32_t mac_lo, uint16_t mac_hi);

/* VLAN */

void action_set_vlan_vid(struct action_context *ctx, uint16_t vlan_vid);
void action_set_vlan_pcp(struct action_context *ctx, uint8_t vlan_pcp);
void action_pop_vlan(struct action_context *ctx);
void action_push_vlan(struct action_context *ctx);

/* IPv4 */

void action_set_ipv4_dst(struct action_context *ctx, uint32_t ipv4);
void action_set_ipv4_src(struct action_context *ctx, uint32_t ipv4);
void action_set_ipv4_dscp(struct action_context *ctx, uint8_t ip_dscp);
void action_set_ipv4_ecn(struct action_context *ctx, uint8_t ip_ecn);
void action_set_ipv4_ttl(struct action_context *ctx, uint8_t ttl);

/* IPv6 */

void action_set_ipv6_dst(struct action_context *ctx, of_ipv6_t ipv6);
void action_set_ipv6_src(struct action_context *ctx, of_ipv6_t ipv6);
void action_set_ipv6_dscp(struct action_context *ctx, uint8_t ip_dscp);
void action_set_ipv6_ecn(struct action_context *ctx, uint8_t ip_ecn);
void action_set_ipv6_ttl(struct action_context *ctx, uint8_t ttl);
void action_set_ipv6_flabel(struct action_context *ctx, uint32_t flabel);

/* TCP */

void action_set_tcp_src(struct action_context *ctx, uint16_t tcp_src);
void action_set_tcp_dst(struct action_context *ctx, uint16_t tcp_dst);

/* UDP */

void action_set_udp_src(struct action_context *ctx, uint16_t udp_src);
void action_set_udp_dst(struct action_context *ctx, uint16_t udp_dst);

/* Misc */

void action_set_priority(struct action_context *ctx, uint32_t priority);
]]

local simple_actions = {
    "controller", "output", "output_local", "output_in_port",
    "set_vlan_vid", "set_vlan_pcp", "pop_vlan", "push_vlan",
    "set_ipv4_dst", "set_ipv4_src", "set_ipv4_dscp", "set_ipv4_ecn", "set_ipv4_ttl",
    "set_ipv6_dscp", "set_ipv6_ecn", "set_ipv6_ttl", "set_ipv6_flabel",
    "set_tcp_src", "set_tcp_dst",
    "set_udp_src", "set_udp_dst",
    "set_priority",
}

for i, action in ipairs(simple_actions) do
    sandbox[action] = function (...)
        C["action_" .. action](context.actx, ...)
    end
end

function sandbox.set_eth_dst(mac_lo, mac_hi)
    C.action_set_eth_dst_scalar(context.actx, mac_lo, mac_hi)
end

function sandbox.set_eth_src(mac_lo, mac_hi)
    C.action_set_eth_src_scalar(context.actx, mac_lo, mac_hi)
end

-- TODO set_ipv6_dst
-- TODO set_ipv6_src
