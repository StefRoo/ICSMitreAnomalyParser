using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class ProfinetRpcDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "version")]
        public string Version { get; internal set; }

        [DataMember(Name = "packet_type")]
        public string PacketType { get; internal set; }

        [DataMember(Name = "object_uuid")]
        public string ObjectUUID { get; internal set; }

        [DataMember(Name = "interface_uuid")]
        public string InterfaceUUID { get; internal set; }

        [DataMember(Name = "activity_uuid")]
        public string ActivityUUID { get; internal set; }

        [DataMember(Name = "server_boot_time")]
        public string ServerBootTime { get; internal set; }

        [DataMember(Name = "operation")]
        public string Operation { get; internal set; }
    }
}
