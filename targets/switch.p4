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
    return ingress;
}



/* Parser END */

/*
 * Metadata START
 */


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

/* Compound action END */


/*
 * Table START
 *
 */

table forward_table {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        forward;
        _drop;
    }
    size: 1024;
}


/* 
 * Control START
 */

control ingress {
    apply(forward_table);
}

/* Control END */
