@load base/frameworks/notice

# Flags any S7Comm or ISO-COTP command going over the wire that is not in a whitelist.

module S7CommLogging;

export {
    redef enum Notice::Type += {
        IsoCotp,
        S7CommData
    };
    
	# ADJUST TO OWN ENVIRONMENT!
    global whitelist: set[addr] = {10.20.2.10, 10.20.0.55, 10.20.2.11};
}

event iso_cotp(c: connection, is_orig: bool, pdu_type: count)
{
	if(c$id$orig_h !in whitelist || c$id$resp_h !in whitelist)
	{
		NOTICE([$note=S7CommLogging::IsoCotp,
	        $msg=fmt("An ISO COTP command has been issued (%s) from %s to %s.", pdu_type, c$id$orig_h, c$id$resp_h),
	        $conn=c]);
	}
    
}

event s7comm_data(c: connection, is_orig: bool, data: string)
{
	if(c$id$orig_h !in whitelist || c$id$resp_h !in whitelist)
	{
		NOTICE([$note=S7CommLogging::S7CommData,
	        $msg=fmt("S7Comm data has been sent (%s) from %s to %s.", data, c$id$orig_h, c$id$resp_h),
	        $conn=c]);
	}
}
