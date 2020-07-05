@load base/frameworks/notice

# Flags both successful and unsuccessful telnet connection attempts as potential anomalies.

module TelnetShell;

export {
    redef enum Notice::Type += {
        LoginSuccess,
        LoginFailure
    };
    
    global ports : set[port] { 23/tcp };
}

event zeek_init()
	{
		Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, ports);
	}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
    NOTICE([$note=TelnetShell::LoginSuccess,
        $msg=fmt("A successful attempt has been made to set up a Telnet connection by user %s with password %s.", client_user, password),
        $conn=c]);
}

event login_failure(c: connection, user: string, client_user: string, password: string, line: string)
{
    NOTICE([$note=TelnetShell::LoginFailure,
        $msg=fmt("An unsuccessful attempt has been made to set up a Telnet connection by user %s with password %s.", client_user, password),
        $conn=c]);
}
