using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class DnsDataLine : DataLine
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

        [DataMember(Name = "trans_id")]
        public string TransportId { get; internal set; }

        [DataMember(Name = "rtt")]
        public string RoundTripTime { get; internal set; }

        [DataMember(Name = "query")]
        public string Query { get; internal set; }

        [DataMember(Name = "qclass")]
        public string QueryClass { get; internal set; }

        [DataMember(Name = "qclass_name")]
        public string QueryClassName { get; internal set; }

        [DataMember(Name = "qtype")]
        public string QueryType { get; internal set; }

        [DataMember(Name = "qtype_name")]
        public string QueryTypeName { get; internal set; }

        [DataMember(Name = "rcode")]
        public string ResponseCode { get; internal set; }

        [DataMember(Name = "rcode_name")]
        public string ResponceCodeName { get; internal set; }

        [DataMember(Name = "AA")]
        public string HasAAFlag { get; internal set; }

        [DataMember(Name = "TC")]
        public string HasTCFlag { get; internal set; }

        [DataMember(Name = "RD")]
        public string HasRDFlag { get; internal set; }

        [DataMember(Name = "RA")]
        public string HasRAFlag { get; internal set; }

        [DataMember(Name = "Z")]
        public string HasZFlag { get; internal set; }

        [DataMember(Name = "answers")]
        public IEnumerable<string> Answers { get; internal set; }

        [DataMember(Name = "TTLs")]
        public IEnumerable<string> TTLs { get; internal set; }

        [DataMember(Name = "rejected")]
        public string Rejected { get; internal set; }
    }
}
