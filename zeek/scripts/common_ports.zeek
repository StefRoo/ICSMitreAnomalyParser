@load base/frameworks/notice

# Checks connections for the use of common ports as defined below, raises a notice is so.

module CommonPorts;

export {
    redef enum Notice::Type += {
        Common_Port
};

global common_ports: set[port] = {
    443/tcp,
    80/tcp,
    53/tcp,
	53/udp,
	5353/tcp,
	5353/udp,
	8080/tcp,
	23/tcp,
	161/udp,
	502/tcp,
	102/tcp,
	20000/tcp,
	44818/tcp,
	22/tcp
    };
}

event connection_successful(c: connection)
{
	if ( c$id$orig_p in CommonPorts::common_ports || c$id$resp_p in CommonPorts::common_ports)
		NOTICE([$note=CommonPorts::Common_Port,
			$msg=fmt("A commonly used port is being used. Sender port: %s. Receiver port: %s", c$id$orig_p, c$id$resp_p),
			$conn=c,
			$identifier=cat(c$id$orig_p)]);
}
