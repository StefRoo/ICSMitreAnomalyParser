@load base/frameworks/notice

# Flags both successful and unsuccessful SSH connection attempts as potential anomalies.

module SecureShell;

export {
    redef enum Notice::Type += {
        SshSuccess,
        SshFailure
    };
}

event ssh_auth_successful(c: connection, auth_method_none: bool)
{
    NOTICE([$note=SecureShell::SshSuccess,
        $msg=fmt("A successful attempt has been made to set up a Ta ssh connection."),
        $conn=c]);
}

event ssh_auth_failed(c: connection)
{
    NOTICE([$note=SecureShell::SshFailure,
        $msg=fmt("An unsuccessful attempt has been made to set up a ssh connection."),
        $conn=c]);
}
