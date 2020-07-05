@load base/frameworks/notice

# Flags Profinet commands going over the wire.

module ProfinetLogging;

export {
    redef enum Notice::Type += {
        ProfinetDceRpc,
        Profinet,
    };
}

event profinet_dce_rpc(c: connection,
                        is_orig: bool,
                        version: count,
                        packet_type: count,
                        object_uuid_part1: count,
                        object_uuid_part2: count,
                        object_uuid_part3: count,
                        object_uuid_part4: count,
                        object_uuid_part5: string,
                        interface_uuid_part1: count,
                        interface_uuid_part2: count,
                        interface_uuid_part3: count,
                        interface_uuid_part4: count,
                        interface_uuid_part5: string,
                        activity_uuid_part1: count,
                        activity_uuid_part2: count,
                        activity_uuid_part3: count,
                        activity_uuid_part4: count,
                        activity_uuid_part5: string,
                        server_boot_time: count,
                        operation_number: count)
{
    NOTICE([$note=ProfinetLogging::ProfinetDceRpc,
        $msg=fmt("A Profinet DCE-RPC command has been issued. Packet type: %s. Operation number: %s", packet_type, operation_number),
        $conn=c]);
}

event profinet(c: connection,
                is_orig: bool,
                operation_type: count,
                block_version_high: count,
                block_version_low: count,
                slot_number: count,
                subslot_number: count,
                index: count)
{
    NOTICE([$note=ProfinetLogging::Profinet,
        $msg=fmt("A Profinet command has been issued: %s", operation_type),
        $conn=c]);
}
