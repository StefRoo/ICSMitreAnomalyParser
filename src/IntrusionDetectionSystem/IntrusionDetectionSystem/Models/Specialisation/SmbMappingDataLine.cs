using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class SmbMappingDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "path")]
        public string Path { get; internal set; }

        [DataMember(Name = "service")]
        public string Service { get; internal set; }

        [DataMember(Name = "native_file_system")]
        public string NativeFileSystem { get; internal set; }

        [DataMember(Name = "share_type")]
        public string ShareType { get; internal set; }
    }
}
