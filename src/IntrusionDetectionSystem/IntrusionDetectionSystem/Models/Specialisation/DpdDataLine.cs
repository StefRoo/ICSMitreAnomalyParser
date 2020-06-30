using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class DpdDataLine : DataLine
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

        [DataMember(Name = "analyzer")]
        public string Analyzer { get; internal set; }

        [DataMember(Name = "failure_reason")]
        public string FailureReason { get; internal set; }
    }
}
