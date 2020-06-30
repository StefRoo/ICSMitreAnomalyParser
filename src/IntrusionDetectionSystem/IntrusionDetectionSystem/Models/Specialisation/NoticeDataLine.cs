using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class NoticeDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "fuid")]
        public string FileUid { get; internal set; }

        [DataMember(Name = "file_mime_type")]
        public string FileMimeType { get; internal set; }

        [DataMember(Name = "file_desc")]
        public string FileDescription { get; internal set; }

        [DataMember(Name = "proto")]
        public string Protocol { get; internal set; }

        [DataMember(Name = "note")]
        public string NoticeType { get; internal set; }

        [DataMember(Name = "msg")]
        public string Message { get; internal set; }

        [DataMember(Name = "sub")]
        public string SubMessage { get; internal set; }

        [DataMember(Name = "src")]
        public string Source { get; internal set; }

        [DataMember(Name = "dst")]
        public string Destination { get; internal set; }

        [DataMember(Name = "p")]
        public string AssociatedPort { get; internal set; }

        [DataMember(Name = "n")]
        public string Amount { get; internal set; }

        [DataMember(Name = "peer_descr")]
        public string PeerDescription { get; internal set; }

        [DataMember(Name = "actions")]
        public IEnumerable<string> Actions { get; internal set; }

        [DataMember(Name = "suppress_for")]
        public string SuppressFor { get; internal set; }

        [DataMember(Name = "dropped")]
        public string SrcIpIsDropped { get; internal set; }
    }
}
