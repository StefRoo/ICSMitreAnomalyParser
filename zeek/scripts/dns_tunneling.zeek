@load base/frameworks/notice

# Flags any dns request with a query longer than 52 as suspicious, as well as the 
# obvious presence of a DnsCat tunnel.

module DNS_TUNNELS;

export {
    
    redef enum Notice::Type += {
        OversizedQuery,
        DnsCat
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
		local elements = split_string(query, /\./);
		if((|elements| > 1) && elements[0] == "dnscat")
		{
			NOTICE([$note=DNS_TUNNELS::DnsCat,
					$conn=c,
					$msg="DNS tunneling detected."]);
		}
	
	    # As seen in https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152# 5.1.1
		if(|query| > 52)
		{
			NOTICE([$note=DNS_TUNNELS::OversizedQuery,
					$conn=c,
					$msg="Possible DNS tunneling detected."]);
		}
	}
