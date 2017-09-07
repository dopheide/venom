# Signature information based on https://cern.ch/security/venom.shtml
# Also thanks to Fatema for contributions to more accurate signatures

# NOTE:  The payload is in the SYN packet so ip-proto==tcp breaks the signature match

signature VENOM-potential {
  payload /.*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\|[0-9]{1,5}).*/
  event "Potential VENOM Scanner"
  tcp-state originator
}

signature VENOM-exact {
  payload /(.*SSH-2\.5-OpenSSH_6\.1\.9.[0-9\.]{7,15}\|[0-9]{1,5}).*/
  event "VENOM Scanner EXACT"
  tcp-state originator
}









