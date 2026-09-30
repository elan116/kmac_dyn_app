// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

class kmac_env extends cip_base_env #(
    .CFG_T              (kmac_env_cfg),
    .COV_T              (kmac_env_cov),
    .VIRTUAL_SEQUENCER_T(kmac_virtual_sequencer),
    .SCOREBOARD_T       (kmac_scoreboard)
  );
  `uvm_component_utils(kmac_env)

  `uvm_component_new

  // The first three app IDs use the existing one-request/one-response static host agent.
  kmac_app_host_agent m_kmac_app_agent[3];
  // OTBN is a dynamic session protocol; keep its component path and monitor stream distinct.
  kmac_app_dynamic_host_agent m_dynamic_app_agent;
  key_sideload_agent  keymgr_sideload_agent;

  // Select and construct the response-ready policy for one KMAC application interface. Each
  // interface has its own policy object so that response backpressure can be varied independently.
  // The global plusargs provide defaults for every interface. The indexed plusargs override those
  // defaults for one interface: +kmac_app_rsp_ready_policy_<index>=<policy> and
  // +kmac_app_max_stall_cycles_<index>=<cycles>. If no policy plusarg is supplied, "always" is
  // used; if no max-stall plusarg is supplied, the config default is retained.
  function void configure_rsp_ready_policy(int unsigned app_idx);
    string policy_name;
    string plusarg_name;
    int unsigned max_stall_cycles;

    policy_name = "always";
    void'($value$plusargs("kmac_app_rsp_ready_policy=%0s", policy_name));

    plusarg_name = $sformatf("kmac_app_rsp_ready_policy_%0d=%%0s", app_idx);
    void'($value$plusargs(plusarg_name, policy_name));

    max_stall_cycles = cfg.m_kmac_app_agent_cfg[app_idx].max_rsp_ready_delay;
    void'($value$plusargs("kmac_app_max_stall_cycles=%0d", max_stall_cycles));

    plusarg_name = $sformatf("kmac_app_max_stall_cycles_%0d=%%0d", app_idx);
    void'($value$plusargs(plusarg_name, max_stall_cycles));
    cfg.m_kmac_app_agent_cfg[app_idx].max_rsp_ready_delay = max_stall_cycles;

    // Create the concrete policy through the per-interface agent configuration.
    case (policy_name)
      "always": cfg.m_kmac_app_agent_cfg[app_idx].rsp_ready_policy =
          kmac_app_rsp_ready_always_policy::type_id::create(policy_name);
      "always_with_dip": cfg.m_kmac_app_agent_cfg[app_idx].rsp_ready_policy =
          kmac_app_rsp_ready_always_with_dip_policy::type_id::create(policy_name);
      "random": cfg.m_kmac_app_agent_cfg[app_idx].rsp_ready_policy =
          kmac_app_rsp_ready_random_policy::type_id::create(policy_name);
      "when_valid": cfg.m_kmac_app_agent_cfg[app_idx].rsp_ready_policy =
          kmac_app_rsp_ready_when_valid_policy::type_id::create(policy_name);
      default: `uvm_fatal(`gfn, $sformatf(
          "Unknown response-ready policy for app interface %0d: %0s",
          app_idx, policy_name))
    endcase
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);

    // Preserve the historical indexed UVM names for KeyMgr, LC_CTRL and ROM_CTRL. OTBN is
    // constructed separately below because its monitor must collect request and response streams
    // concurrently rather than pairing one request packet with one response.
    for (int i = 0; i < 3; i++) begin
      string name = $sformatf("m_kmac_app_agent[%0d]", i);
      configure_rsp_ready_policy(i);
      m_kmac_app_agent[i] = kmac_app_host_agent::type_id::create(name, this);
      uvm_config_db#(kmac_app_agent_cfg)::set(this, name, "cfg", cfg.m_kmac_app_agent_cfg[i]);
    end

    // AppOtbn remains index 3 in configuration/scoreboard arrays even though its UVM component has
    // a semantic name rather than occupying element 3 of the static agent array.
    configure_rsp_ready_policy(kmac_env_pkg::AppOtbn);
    cfg.m_kmac_app_agent_cfg[kmac_env_pkg::AppOtbn].is_dynamic_app = 1'b1;
    m_dynamic_app_agent = kmac_app_dynamic_host_agent::type_id::create("m_dynamic_app_agent", this);
    uvm_config_db#(kmac_app_agent_cfg)::set(this, "m_dynamic_app_agent", "cfg",
                                            cfg.m_kmac_app_agent_cfg[kmac_env_pkg::AppOtbn]);

    // get ext interfaces
    keymgr_sideload_agent = key_sideload_agent#(keymgr_pkg::hw_key_req_t)::type_id::create(
      "keymgr_sideload_agent", this);
    uvm_config_db#(key_sideload_agent_cfg#(keymgr_pkg::hw_key_req_t))::set(
      this, "keymgr_sideload_agent*", "cfg", cfg.keymgr_sideload_agent_cfg);

    // config kmac virtual interface
    if (!uvm_config_db#(kmac_vif)::get(this, "", "kmac_vif", cfg.kmac_vif)) begin
      `uvm_fatal(`gfn, "failed to get kmac_vif from uvm_config_db")
    end

    // If masking is enabled, there should be an instance of reqack_data_if available
    if (cfg.kmac_vif.en_masking_o) begin
      if (!uvm_config_db#(virtual pins_if #(1))::get(this, "", "reqack_data_pins_vif",
                                                     cfg.disable_reqack_assertions_vif)) begin
        `uvm_fatal(get_full_name(), "Failed to get reqack_data_pins_vif from uvm_config_db.")
      end
    end

  endfunction

  function void connect_phase(uvm_phase phase);
    super.connect_phase(phase);

    // Keep all passive monitor traffic routed to its original hardware app-ID slot. Scoreboard
    // indexing is by AppKeymgr/AppLc/AppRom/AppOtbn, not by the new component-array layout.
    for (int i = 0; i < 3; i++) begin
      m_kmac_app_agent[i].monitor.analysis_port.connect(
        scoreboard.kmac_app_fifo[i].analysis_export);
      m_kmac_app_agent[i].monitor.m_req_analysis_port.connect(
        scoreboard.m_app_req_fifos[i].analysis_export);

      virtual_sequencer.kmac_app_sequencer_h[i]  = m_kmac_app_agent[i].sequencer;
    end
    m_dynamic_app_agent.monitor.analysis_port.connect(
      scoreboard.kmac_app_fifo[kmac_env_pkg::AppOtbn].analysis_export);
    m_dynamic_app_agent.monitor.m_req_analysis_port.connect(
      scoreboard.m_app_req_fifos[kmac_env_pkg::AppOtbn].analysis_export);
    m_dynamic_app_agent.monitor.m_rsp_analysis_port.connect(
      scoreboard.m_app_rsp_fifos[kmac_env_pkg::AppOtbn].analysis_export);

    // Preserve the old indexed sequencer handle for callers that still use app IDs; also expose an
    // explicit dynamic handle to make dynamic-session sequence selection clear at call sites.
    virtual_sequencer.kmac_app_sequencer_h[kmac_env_pkg::AppOtbn] =
        m_dynamic_app_agent.sequencer;
    virtual_sequencer.dynamic_app_sequencer_h = m_dynamic_app_agent.sequencer;
    virtual_sequencer.key_sideload_sequencer_h = keymgr_sideload_agent.sequencer;
    cfg.keymgr_sideload_agent_cfg.start_default_seq = 0;

  endfunction

endclass
