using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class DhcpDataLine : DataLine
    {
        [DataMember(Name = "uids")]
        public IEnumerable<string> Uids { get; internal set; }

        [DataMember(Name = "client_addr")]
        public string ClientAddress { get; internal set; }

        [DataMember(Name = "server_addr")]
        public string ServerAddress { get; internal set; }

        [DataMember(Name = "mac")]
        public string MAC { get; internal set; }

        [DataMember(Name = "host_name")]
        public string HostName { get; internal set; }

        [DataMember(Name = "client_fqdn")]
        public string ClientFQDN { get; internal set; }

        [DataMember(Name = "domain")]
        public string Domain { get; internal set; }

        [DataMember(Name = "requested_addr")]
        public string RequestedAddress { get; internal set; }

        [DataMember(Name = "assigned_addr")]
        public string AssignedAddress { get; internal set; }

        [DataMember(Name = "lease_time")]
        public string LeaseTime { get; internal set; }

        [DataMember(Name = "client_message")]
        public string ClientMessage { get; internal set; }

        [DataMember(Name = "server_message")]
        public string ServerMessage { get; internal set; }

        [DataMember(Name = "msg_types")]
        public IEnumerable<string> MessageTypes { get; internal set; }

        [DataMember(Name = "duration")]
        public string Duration { get; internal set; }
    }
}
