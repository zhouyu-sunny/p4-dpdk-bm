/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "p4src/includes/headers.p4"
#include "p4src/includes/intrinsic.p4"




/*  
 *  Parser START
 *  L2: ethernet
 *  L3: IPv4
 *  L4: TCP UDP
*/

#define ETHERTYPE_IPV4          0x0800

#define IP_PROTOCOLS_IPHL_TCP   0x506
#define IP_PROTOCOLS_IPHL_UDP   0x511

header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t udp;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;                      
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);

    return select(latest.fragOffset, latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_TCP : parse_tcp;
        IP_PROTOCOLS_IPHL_UDP : parse_udp;
        default: ingress;
    }
}



parser parse_udp {
    extract(udp);
    
    return ingress;
}

parser parse_tcp {
    extract(tcp);
    
    return ingress;
}



/* Parser END */

/*
 * Metadata START
 */

header_type state_metadata_t {
    fields {
        target_id   : 16;
        register_id : 16;
        cur_state   : 8;
        trigger     : 8;
        
    }
}

metadata state_metadata_t state_metadata;


/* Metadata END */


field_list state_learn {
    state_metadata.cur_state;
    state_metadata.target_id;
    state_metadata.register_id;
    
}

/*
 * Stateful memory START
 *
 */

 register state_register {
    width : 8;
    instance_count : 1024;
 }

/* Stateful END */

/* 
 * Compound action START 
 */

action _drop() {
    drop();
}

action alert() {
    drop();
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}


action get_state(target_id, register_id) {
    modify_field(state_metadata.target_id, target_id);
    register_read(state_metadata.cur_state, state_register, register_id);
    modify_field(state_metadata.trigger, tcp.flags);
    modify_field(state_metadata.register_id, register_id);
    generate_digest(1, state_learn);
    // Read the current state
    // Read the state transfering trigger
}

action state_transfer(next_state) {
    register_write(state_register, state_metadata.register_id, next_state);
}

action broadcast() {
    modify_field(standard_metadata.egress_spec, (standard_metadata.ingress_port%2+1));
}

/* Compound action END */


/*
 * Table START
 *
 */

table forward_table {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        forward;
        _drop;
    }
    size: 1024;
}

table match_state_table {
    reads {
        ethernet.dstAddr :exact;
        //ipv4.dstAddr : exact;
        //ipv4.srcAddr : exact;
        //tcp.dstPort  : exact;
        //tcp.srcPort  : exact;
        //tcp.flags    : exact;

    }
    actions {
        get_state;
    }
    size: 1024;
}

table state_transfer_table {
    reads {
        state_metadata.target_id : exact;
        state_metadata.cur_state : exact;
        state_metadata.trigger   : exact;
    }
    actions {
        state_transfer;
        alert;
    }
    size: 1024;
}


/* 
 * Control START
 */

control ingress {
    apply(forward_table);
    apply(match_state_table) {
        hit {
            apply(state_transfer_table);
        }
    }
}

/* Control END */
