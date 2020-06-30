using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class NtpDataLine : DataLine
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

        [DataMember(Name = "mode")]
        public string Mode { get; internal set; }

        [DataMember(Name = "stratum")]
        public string Stratum { get; internal set; }

        [DataMember(Name = "poll")]
        public string Poll { get; internal set; }

        [DataMember(Name = "precision")]
        public string Precision { get; internal set; }

        [DataMember(Name = "root_delay")]
        public string RootDelay { get; internal set; }

        [DataMember(Name = "root_disp")]
        public string RootDisp { get; internal set; }

        [DataMember(Name = "ref_id")]
        public string ReferenceId { get; internal set; }

        [DataMember(Name = "org_time")]
        public string OrgTime { get; internal set; }

        [DataMember(Name = "rec_time")]
        public string RecTime { get; internal set; }

        [DataMember(Name = "xmt_time")]
        public string XmtTime { get; internal set; }

        [DataMember(Name = "num_exts")]
        public string NumExts { get; internal set; }
    }
}
