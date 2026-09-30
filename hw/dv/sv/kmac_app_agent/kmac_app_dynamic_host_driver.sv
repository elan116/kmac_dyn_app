// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Dynamic host driver specialization. It intentionally adds no alternate pin-driving algorithm:
// request valid/ready and response valid/ready handshakes are identical for static and dynamic
// links. Session-specific sequencing (configuration, message, output drain, termination) belongs
// in kmac_app_dynamic_host_seq, while this subtype gives UVM factory/configuration a distinct type.
class kmac_app_dynamic_host_driver extends kmac_app_host_driver;
  `uvm_component_utils(kmac_app_dynamic_host_driver)

  extern function new(string name, uvm_component parent);
endclass

function kmac_app_dynamic_host_driver::new(string name, uvm_component parent);
  super.new(name, parent);
endfunction
