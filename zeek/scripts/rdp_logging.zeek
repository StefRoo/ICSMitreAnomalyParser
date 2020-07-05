@load base/frameworks/notice

# Flags both successful and unsuccessful RDP connection attempts as potential anomalies.

module RDPDetection;

export {
    redef enum Notice::Type += {
        RDPSuccess,
        RDPFailure
    };
}

event RDP::log_rdp(rec: RDP::Info)
	{
		if(rec$result == "encrypted" || rec$result == "Success")
		{
			NOTICE([$note=RDPDetection::RDPSuccess,
		        $msg=fmt("A successful attempt has been made to set up an RDP connection."),
		        $uid=rec$uid,
		        $id=rec$id]);
		}
		else
		{
			NOTICE([$note=RDPDetection::RDPFailure,
		        $msg=fmt("An unsuccessful attempt has been made to set up an RDP connection."),
		        $uid=rec$uid,
		        $id=rec$id]);
		}
	}
