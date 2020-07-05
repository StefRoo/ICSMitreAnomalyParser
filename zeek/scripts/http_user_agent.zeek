@load base/frameworks/notice

# Flags HTTP connections using the MicroBrowser user agent that are not in a certain whitelist.

module HTTP_USER_AGENT;

export {
    
    redef enum Notice::Type += {
        MicroBrowser
    };
    
	# ADJUST TO OWN ENVIRONMENT!
    global whitelist: set[addr] = {
    	10.20.3.11,
    	10.20.3.10
    };
}

event http_stats(c: connection, stats: http_stats_rec)
	{
		if(c?$http)
		{
			if(c$http?$user_agent)
			{
				if(strcmp(c$http$user_agent[:12], "MicroBrowser") == 0)
				{
					if(c$id$orig_h !in whitelist || c$id$resp_h !in whitelist)
					{
						NOTICE([$note=HTTP_USER_AGENT::MicroBrowser,
								$msg="An HTTP request has been done by a MicroBrowser user agent.",
								$conn=c]);
					}
				}
			}
		}
	}
