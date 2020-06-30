using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class SmbFilesDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "fuid")]
        public string FileUid { get; internal set; }

        [DataMember(Name = "action")]
        public string Action { get; internal set; }

        [DataMember(Name = "path")]
        public string Path { get; internal set; }

        [DataMember(Name = "name")]
        public string Name { get; internal set; }

        [DataMember(Name = "size")]
        public string Size { get; internal set; }

        [DataMember(Name = "prev_name")]
        public string PreviousName { get; internal set; }

        [DataMember(Name = "times.modified")]
        public string LastModifyTime { get; internal set; }

        [DataMember(Name = "times.accessed")]
        public string LastAccessTime { get; internal set; }

        [DataMember(Name = "times.created")]
        public string LastCreateTime { get; internal set; }

        [DataMember(Name = "times.changed")]
        public string LastChangeTime { get; internal set; }
    }
}
