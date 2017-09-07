module Site;

#redef exit_only_after_terminate = T;

# file containing signature
redef signature_files += "venom.sig";
redef FilteredTraceDetection::enable = F;
export {
        redef enum Notice::Type += {
                VENOM_SCANNER,
                VENOM_SCANNER_EXACT,
                VENOM_CALLBACK
        };

        global venom_callback_addrs: set[addr,port] &write_expire=2days;

        global Site::w_m_new_venom: event(a: addr, p: port);
        global Site::m_w_add_venom: event(a: addr, p: port);
}

# Using Aashish's style of cluster communication
@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Site::m_w_add_venom/;
redef Cluster::worker2manager_events += /Site::w_m_new_venom/;
@endif

event bro_done(){
  for([x,y] in venom_callback_addrs){
    print fmt("%s %s",x,y);
  }

}

event connection_established(c: connection){
  if([c$id$resp_h,c$id$resp_p] in venom_callback_addrs){
    #ruh roe
    NOTICE([$note=VENOM_CALLBACK,
            $conn=c,
            $msg=fmt("VENOM WARNING: %s connected back to %s", c$id$orig_h, c$id$resp_h),
            $identifier=cat(c$id$orig_h,c$id$resp_h)]);
  } 
}

### In sig match, pull out the IP/port for the callback.

event signature_match(state: signature_state, msg: string, data: string){
  local venom_addrs: vector of string;
  local v_addr: addr;
  local v_port: port;
  local v_strs: vector of string;
    if (/^VENOM-exact$/ in state$sig_id){
      NOTICE([$note=VENOM_SCANNER_EXACT,
       				$conn=state$conn, $msg=fmt("%s likely target of VENOM Scanner", state$conn$id$resp_h),
       				$identifier=cat(state$conn$id$resp_h)]);
    }
    if (/^VENOM-potential$/ in state$sig_id){
      print fmt("Potential VENOM Scanner");

      # try not to assume too much about where the port data is.
      v_strs = split_string1(data,/\|/);
      for(i in v_strs){
        if(i > 0 && /[0-9]{1,5}/ in v_strs[i] && /[0-9\.]{7,15}/ in v_strs[i-1]){
          v_port = to_port(fmt("%s/tcp",v_strs[i]));
        }
      }
      venom_addrs = extract_ip_addresses(data);
      # there should only be one, but this extract function is handy
      for(i in venom_addrs){
        v_addr = to_addr(venom_addrs[i]);

@if ( Cluster::is_enabled() )
        event Site::w_m_new_venom(v_addr, v_port);
@else
        add venom_callback_addrs[v_addr,v_port];
@endif

      }
      NOTICE([$note=VENOM_SCANNER,
              $conn=state$conn, $msg=fmt("%s potential target of VENOM Scanner", state$conn$id$resp_h),
              $identifier=cat(state$conn$id$resp_h)]);
    }
}

# we don't really even need to keep track of the set on the manager,
# it just needs to communicate the change to the workers?
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event Site::w_m_new_venom(a: addr, p: port)
{
    event Site::m_w_add_venom(a,p);
}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Site::m_w_add_venom(a: addr, p: port){
  add venom_callback_addrs[a,p];
}
@endif



