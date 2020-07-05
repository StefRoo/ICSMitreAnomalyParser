@load base/frameworks/notice

# Watches for portable executable mime types or file extensions going over the wire.

module PortableExecutables;

export {
	redef enum Notice::Type += {
		FtpPE,
		NonFtpPE
	};
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
    	if(c$ftp?$mime_type)
    	{
    		if(c$ftp$mime_type == "application/octet-stream" ||
	    		c$ftp$mime_type == "application/vnd.microsoft.portable-executable" ||
	    		c$ftp$mime_type == "application/bat" ||
				c$ftp$mime_type == "application/x-bat" ||
	    		c$ftp$mime_type == "application/x-msdos-program" ||
	    		c$ftp$mime_type == "application/x-msdownload" ||
	    		c$ftp$mime_type == "application/x-ms-installer" ||
	    		c$ftp$mime_type == "application/x-elf" ||
	    		c$ftp$mime_type == "application/x-sh" ||
	    		c$ftp$mime_type == "text/x-python" ||
	    		c$ftp$mime_type == "text/x-perl" ||
	    		c$ftp$mime_type == "application/x-csh" ||
	    		c$ftp$mime_type == "application/x-dosexec")
	    			NOTICE([$note=PortableExecutables::FtpPE,
						$msg=fmt("A(n) %s executable has been sent using FTP", c$ftp$mime_type),
						$conn=c]);
    	}
    	else if(c$ftp?$arg)
    	{
    		if(strstr(c$ftp$arg, ".bin") != 0 ||
				strstr(c$ftp$arg, ".acm") != 0||
				strstr(c$ftp$arg, ".ax") != 0||
				strstr(c$ftp$arg, ".cpl") != 0||
				strstr(c$ftp$arg, ".dll") != 0||
				strstr(c$ftp$arg, ".drv") != 0||
				strstr(c$ftp$arg, ".efi") != 0||
				strstr(c$ftp$arg, ".exe") != 0||
				strstr(c$ftp$arg, ".mui") != 0||
				strstr(c$ftp$arg, ".ocx") != 0||
				strstr(c$ftp$arg, ".scr") != 0||
				strstr(c$ftp$arg, ".sys") != 0||
				strstr(c$ftp$arg, ".tsp") != 0||
				strstr(c$ftp$arg, ".bat") != 0||
				strstr(c$ftp$arg, ".cmd") != 0||
				strstr(c$ftp$arg, ".btm") != 0||
				strstr(c$ftp$arg, ".msi") != 0||
				strstr(c$ftp$arg, ".axf") != 0||
				strstr(c$ftp$arg, ".elf") != 0||
				strstr(c$ftp$arg, ".o") != 0||
				strstr(c$ftp$arg, ".prx") != 0||
				strstr(c$ftp$arg, ".puff") != 0||
				strstr(c$ftp$arg, ".ko") != 0||
				strstr(c$ftp$arg, ".mod") != 0||
				strstr(c$ftp$arg, ".so") != 0||
				strstr(c$ftp$arg, ".sh") != 0||
				strstr(c$ftp$arg, ".py") != 0||
				strstr(c$ftp$arg, ".pl") != 0||
				strstr(c$ftp$arg, ".csh") != 0)
    		{
    			NOTICE([$note=PortableExecutables::FtpPE,
						$msg=fmt("A(n) %s executable has been sent using FTP", c$ftp$arg),
						$conn=c]);
			}
    			
    	}
	}

event ftp_request(c: connection, command: string, arg: string)
    {
    	if(c$ftp?$mime_type)
    	{
    		if(c$ftp$mime_type == "application/octet-stream" ||
	    		c$ftp$mime_type == "application/vnd.microsoft.portable-executable" ||
	    		c$ftp$mime_type == "application/bat" ||
				c$ftp$mime_type == "application/x-bat" ||
	    		c$ftp$mime_type == "application/x-msdos-program" ||
	    		c$ftp$mime_type == "application/x-msdownload" ||
	    		c$ftp$mime_type == "application/x-ms-installer" ||
	    		c$ftp$mime_type == "application/x-elf" ||
	    		c$ftp$mime_type == "application/x-sh" ||
	    		c$ftp$mime_type == "text/x-python" ||
	    		c$ftp$mime_type == "text/x-perl" ||
	    		c$ftp$mime_type == "application/x-csh" ||
	    		c$ftp$mime_type == "application/x-dosexec")
	    			NOTICE([$note=PortableExecutables::FtpPE,
						$msg=fmt("A(n) %s executable has been sent using FTP", c$ftp$mime_type),
						$conn=c]);
    	}
    	else if(arg != "")
    	{
    		if(strstr(c$ftp$arg, ".bin") != 0 ||
				strstr(c$ftp$arg, ".acm") != 0||
				strstr(c$ftp$arg, ".ax") != 0||
				strstr(c$ftp$arg, ".cpl") != 0||
				strstr(c$ftp$arg, ".dll") != 0||
				strstr(c$ftp$arg, ".drv") != 0||
				strstr(c$ftp$arg, ".efi") != 0||
				strstr(c$ftp$arg, ".exe") != 0||
				strstr(c$ftp$arg, ".mui") != 0||
				strstr(c$ftp$arg, ".ocx") != 0||
				strstr(c$ftp$arg, ".scr") != 0||
				strstr(c$ftp$arg, ".sys") != 0||
				strstr(c$ftp$arg, ".tsp") != 0||
				strstr(c$ftp$arg, ".bat") != 0||
				strstr(c$ftp$arg, ".cmd") != 0||
				strstr(c$ftp$arg, ".btm") != 0||
				strstr(c$ftp$arg, ".msi") != 0||
				strstr(c$ftp$arg, ".axf") != 0||
				strstr(c$ftp$arg, ".elf") != 0||
				strstr(c$ftp$arg, ".o") != 0||
				strstr(c$ftp$arg, ".prx") != 0||
				strstr(c$ftp$arg, ".puff") != 0||
				strstr(c$ftp$arg, ".ko") != 0||
				strstr(c$ftp$arg, ".mod") != 0||
				strstr(c$ftp$arg, ".so") != 0||
				strstr(c$ftp$arg, ".sh") != 0||
				strstr(c$ftp$arg, ".py") != 0||
				strstr(c$ftp$arg, ".pl") != 0||
				strstr(c$ftp$arg, ".csh") != 0)
    		{
    			NOTICE([$note=PortableExecutables::FtpPE,
						$msg=fmt("A(n) %s executable has been sent using FTP", arg),
						$conn=c]);
			}
    			
    	}
	}

event file_transferred(c: connection, prefix: string, descr: string, mime_type: string)
    {
    	if(mime_type == "application/octet-stream" ||
    		mime_type == "application/vnd.microsoft.portable-executable" ||
    		mime_type == "application/bat" ||
			mime_type == "application/x-bat" ||
    		mime_type == "application/x-msdos-program" ||
    		mime_type == "application/x-msdownload" ||
    		mime_type == "application/x-ms-installer" ||
    		mime_type == "application/x-elf" ||
    		mime_type == "application/x-sh" ||
    		mime_type == "text/x-python" ||
    		mime_type == "text/x-perl" ||
    		mime_type == "application/x-csh" ||
	    	mime_type == "application/x-dosexec")
    			NOTICE([$note=PortableExecutables::NonFtpPE,
					$msg=fmt("A(n) %s executable has been transferred.", mime_type),
					$conn=c]);
	}
