using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class DceRpcDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "rtt")]
        public string RoundTripTime { get; internal set; }

        [DataMember(Name = "named_pipe")]
        public string NamedPipe { get; internal set; }

        [DataMember(Name = "endpoint")]
        public string Endpoint { get; internal set; }

        [DataMember(Name = "operation")]
        public string Operation { get; internal set; }
    }
}
