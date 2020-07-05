# Loads all the scripts created for the IntrusionDetectionSystem project, as well as
# changing the output to JSON for correct processing.

@load arp_spoofing.zeek
@load common_ports.zeek
@load dns_tunneling.zeek
@load ftp_portable_executable.zeek
@load http_post_body.zeek
@load http_user_agent.zeek
@load modbus_logging.zeek
@load profinet_logging.zeek
@load rdp_logging.zeek
@load s7com_cotp_logging.zeek
@load smb_logging.zeek
@load ssh_logging.zeek
@load tcp_scan_detection.zeek
@load telnet_logging.zeek
@load vnc_logging.zeek
@load tuning/json-logs.zeek