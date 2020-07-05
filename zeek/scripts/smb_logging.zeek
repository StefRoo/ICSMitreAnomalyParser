@load base/frameworks/notice

# Flags any SMB1 or SMB2 commands going over the wire if they have to do with altering or reading files.

module SMB_LOGGING;

export {
    
    redef enum Notice::Type += {
        SMB1Command,
        SMB2Command
    };
}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
	{
		if(hdr?$command)
		{
			if(hdr$command == 5 || hdr$command == 6 || hdr$command == 7 || hdr$command == 8 || hdr$command == 9 || hdr$command == 10)
			{
				NOTICE([$note=SMB_LOGGING::SMB1Command,
						$conn=c,
						$msg=fmt("An SMB1 command has been issued. Command: %s", hdr$command)]);
			}
		}
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
	{
		if(hdr?$command)
		{
			if(hdr$command == 5 || hdr$command == 6 || hdr$command == 7 || hdr$command == 8 || hdr$command == 9 || hdr$command == 10)
			{
				NOTICE([$note=SMB_LOGGING::SMB2Command,
						$conn=c,
						$msg=fmt("An SMB2 command has been issued. Command: %s", hdr$command)]);
			}
		}
	}
