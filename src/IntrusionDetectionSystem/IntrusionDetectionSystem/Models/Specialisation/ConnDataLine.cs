using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class ConnDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "proto")]
        public string Protocol { get; internal set; }

        [DataMember(Name = "service")]
        public string ServiceProtocol { get; internal set; }

        [DataMember(Name = "duration")]
        public string Duration { get; internal set; }

        [DataMember(Name = "orig_bytes")]
        public string SourceByteAmount { get; internal set; }

        [DataMember(Name = "resp_bytes")]
        public string DestinationByteAmount { get; internal set; }

        [DataMember(Name = "conn_state")]
        public string ConnectionState { get; internal set; }

        [DataMember(Name = "local_orig")]
        public string IsLocalSource { get; internal set; }

        [DataMember(Name = "local_resp")]
        public string IsLocalDestination { get; internal set; }

        [DataMember(Name = "missed_bytes")]
        public string MissedByteAmount { get; internal set; }

        [DataMember(Name = "history")]
        public string ConnectionStateHistory { get; internal set; }

        [DataMember(Name = "orig_pkts")]
        public string SourcePacketAmount { get; internal set; }

        [DataMember(Name = "orig_ip_bytes")]
        public string SourceIPBytes { get; internal set; }

        [DataMember(Name = "resp_pkts")]
        public string DestinationPacketAmount { get; internal set; }

        [DataMember(Name = "resp_ip_bytes")]
        public string DestinationIPBytes { get; internal set; }

        [DataMember(Name = "tunnel_parents")]
        public string TunnelParents { get; internal set; }
    }
}
