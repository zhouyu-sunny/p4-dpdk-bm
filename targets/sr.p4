#include "p4src/includes/intrinsic.p4"

header_type sr_header_t {
    fields {
        flag : 8;
        nb : 8;
    }
}

header_type sr_label_t {
    fields {
        label : 16; 
    }
}

header_type ethernet_t {
    fields {
        addr : 48;
    }
}

header sr_header_t sr_header;
header sr_label_t sr_label;
header ethernet_t ethernet;


parser start {
    return select(current(0,3)) {
        0x3 : parse_sr;
        default : parse_ethernet;
    }
}

parser parse_sr {
    extract(sr_header);
    extract(sr_label);
    return ingress;
}

parser parse_ethernet {
    extract(ethernet);
    return ingress;
}

action _drop() {
    drop();
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}


action add_sr_header() {
    add_header(sr_header);
    modify_field(sr_header.flag, 0x60);
}

action push_sr_label(label) {
    add_header(sr_label);
    modify_field(sr_label.label, label);
    add_to_field(sr_header.nb, 1);
}

action push_1_sr_label(l1) {
    add_sr_header();
    push_sr_label(l1);
    forward(1);
}

action push_2_sr_label(l1, l2) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
}

action push_3_sr_label(l1, l2, l3) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
}
action push_4_sr_label(l1, l2, l3, l4) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
    push_sr_label(l4);
}
action push_5_sr_label(l1, l2, l3, l4, l5) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
    push_sr_label(l4);
    push_sr_label(l5);
}

action push_6_sr_label(l1, l2, l3, l4, l5, l6) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
    push_sr_label(l4);
    push_sr_label(l5);
    push_sr_label(l6);
}

action push_7_sr_label(l1, l2, l3, l4, l5, l6, l7) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
    push_sr_label(l4);
    push_sr_label(l5);
    push_sr_label(l6);
    push_sr_label(l7);
}


action push_8_sr_label(l1, l2, l3, l4, l5, l6, l7, l8) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
    push_sr_label(l4);
    push_sr_label(l5);
    push_sr_label(l6);
    push_sr_label(l7);
    push_sr_label(l8);
}

action push_9_sr_label(l1, l2, l3, l4, l5, l6, l7, l8, l9) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
    push_sr_label(l4);
    push_sr_label(l5);
    push_sr_label(l6);
    push_sr_label(l7);
    push_sr_label(l8);
    push_sr_label(l9);
}

action push_10_sr_label(l1, l2, l3, l4, l5, l6, l7, l8, l9, l10) {
    add_sr_header();
    push_sr_label(l1);
    push_sr_label(l2);
    push_sr_label(l3);
    push_sr_label(l4);
    push_sr_label(l5);
    push_sr_label(l6);
    push_sr_label(l7);
    push_sr_label(l8);
    push_sr_label(l9);
    push_sr_label(l10);
}

action sr_forward(port) {
    remove_header(sr_label);
    add_to_field(sr_header.nb, -1);
    forward(port);
}

action sr_output(port) {
    remove_header(sr_label);
    remove_header(sr_label);
    forward(port);
}


table push_sr_table {
    reads {
        sr_header : valid;
    }
    actions {
        push_1_sr_label;
        push_2_sr_label;
        push_3_sr_label;
        push_4_sr_label;
        push_5_sr_label;
        push_6_sr_label;
        push_7_sr_label;
        push_8_sr_label;
        push_9_sr_label;
        push_10_sr_label;
    }
    size: 1024;
}

table forward_table {
    reads {
        ethernet.addr : exact;
    }
    actions {
        forward;
    }
}

table sr_table {
    reads {
        sr_label.label : exact;
    }
    actions {
        sr_forward;
        sr_output;
        _drop;
    }
}

control ingress {
    if(valid(ethernet)) {
        apply(push_sr_table);
        apply(forward_table);
    }
    else {
        apply(sr_table);
    }
    
    
}