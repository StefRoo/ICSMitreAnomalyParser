using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class SnmpDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "duration")]
        public string Duration { get; internal set; }

        [DataMember(Name = "version")]
        public string Version { get; internal set; }

        [DataMember(Name = "community")]
        public string Community { get; internal set; }

        [DataMember(Name = "get_requests")]
        public string GetRequests { get; internal set; }

        [DataMember(Name = "get_bulk_requests")]
        public string GetBulkRequests { get; internal set; }

        [DataMember(Name = "get_responses")]
        public string GetResponses { get; internal set; }

        [DataMember(Name = "set_requests")]
        public string SetRequests { get; internal set; }

        [DataMember(Name = "display_string")]
        public string DisplayString { get; internal set; }

        [DataMember(Name = "up_since")]
        public string UpSince { get; internal set; }
    }
}
