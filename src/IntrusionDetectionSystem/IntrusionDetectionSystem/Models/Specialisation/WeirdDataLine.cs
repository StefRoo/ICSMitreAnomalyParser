using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class WeirdDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string SourceAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string SourcePort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string DestinationAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string DestinationPort { get; internal set; }

        [DataMember(Name = "name")]
        public string Name { get; internal set; }

        [DataMember(Name = "addl")]
        public string AdditionalInformation { get; internal set; }

        [DataMember(Name = "notice")]
        public bool? IsNotice { get; internal set; }

        [DataMember(Name = "peer")]
        public string Peer { get; internal set; }
    }
}
