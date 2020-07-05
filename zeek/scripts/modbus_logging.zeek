@load base/frameworks/notice

# Flags MOdbus connections that are not in a certain whitelist.

module ModbusLogging;

export {
    redef enum Notice::Type += {
        ModbusEvent
    };
    
	# ADJUST TO OWN ENVIRONMENT!
    global whitelist: set[addr] = {123.145.120.99, 123.145.120.102};
}

event modbus_message (c: connection, headers: ModbusHeaders, is_orig: bool)
{
	if(c$id$orig_h !in whitelist || c$id$resp_h !in whitelist)
	{
		NOTICE([$note=ModbusLogging::ModbusEvent,
        $msg=fmt("A Modbus command has been issued (%s) from %s to %s.", c$modbus$func, c$id$orig_h, c$id$resp_h),
        $conn=c]);
	}
}