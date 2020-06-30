using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class EnipDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "command")]
        public string CommandType { get; internal set; }

        [DataMember(Name = "length")]
        public string Length { get; internal set; }

        [DataMember(Name = "session_handle")]
        public string SessionHandle { get; internal set; }

        [DataMember(Name = "status")]
        public string StatusCode { get; internal set; }

        [DataMember(Name = "sender_context")]
        public string SenderContext { get; internal set; }

        [DataMember(Name = "options")]
        public string Options { get; internal set; }
    }
}
