using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class FilesDataLine : DataLine
    {
        [DataMember(Name = "fuid")]
        public string FileUid { get; internal set; }

        [DataMember(Name = "tx_hosts")]
        public IEnumerable<string> TxHosts { get; internal set; }

        [DataMember(Name = "rx_hosts")]
        public IEnumerable<string> RxHosts { get; internal set; }

        [DataMember(Name = "conn_uids")]
        public IEnumerable<string> ConnectionUids { get; internal set; }

        [DataMember(Name = "source")]
        public string Source { get; internal set; }

        [DataMember(Name = "depth")]
        public string Depth { get; internal set; }

        [DataMember(Name = "analyzers")]
        public IEnumerable<string> Analyzers { get; internal set; }

        [DataMember(Name = "mime_type")]
        public string MimeType { get; internal set; }

        [DataMember(Name = "filename")]
        public string FileName { get; internal set; }

        [DataMember(Name = "duration")]
        public string Duration { get; internal set; }

        [DataMember(Name = "local_orig")]
        public string SourceIsLocal { get; internal set; }

        [DataMember(Name = "is_orig")]
        public string IsSource { get; internal set; }

        [DataMember(Name = "seen_bytes")]
        public string SeenBytes { get; internal set; }

        [DataMember(Name = "total_bytes")]
        public string TotalBytes { get; internal set; }

        [DataMember(Name = "missing_bytes")]
        public string MissingBytes { get; internal set; }

        [DataMember(Name = "overflow_bytes")]
        public string OverflowBytes { get; internal set; }

        [DataMember(Name = "timedout")]
        public string HasTimedOut { get; internal set; }

        [DataMember(Name = "parent_fuid")]
        public string ParentFileUid { get; internal set; }

        [DataMember(Name = "md5")]
        public string MD5 { get; internal set; }

        [DataMember(Name = "sha1")]
        public string SHA1 { get; internal set; }

        [DataMember(Name = "sha256")]
        public string SHA256 { get; internal set; }

        [DataMember(Name = "extracted")]
        public string Extracted { get; internal set; }

        [DataMember(Name = "extracted_cutoff")]
        public string ExtractedCutOff { get; internal set; }

        [DataMember(Name = "extracted_size")]
        public string ExtractedSize { get; internal set; }
    }
}
