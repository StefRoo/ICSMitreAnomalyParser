@load base/frameworks/notice

# Flags both successful and unsuccessful VNC connection attempts as potential anomalies.

module VNC;

export {
    redef enum Notice::Type += {
        VNCSuccess,
        VNCFailure,
        ClientVersion
    };
}

event rfb_auth_result(c: connection, result: bool)
	{
		if(result)
		{
			NOTICE([$note=VNC::VNCSuccess,
		        $msg=fmt("A successful attempt has been made to set up a VNC connection."),
		        $conn=c]);
		}
		else
		{
			NOTICE([$note=VNC::VNCFailure,
			        $msg=fmt("An unsuccessful attempt has been made to set up a VNC connection."),
			        $conn=c]);
		}
	}

event rfb_client_version(c: connection, major_version: string, minor_version: string)
{
	NOTICE([$note=VNC::ClientVersion,
	        $msg=fmt("A client version has been seen to set up a RFB connection. Client version: %s:%s", major_version, minor_version),
	        $conn=c]);
}
