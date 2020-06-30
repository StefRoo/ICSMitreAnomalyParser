using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class S7CommDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "rosctr")]
        public string RosCtr { get; internal set; }

        [DataMember(Name = "parameter")]
        public IEnumerable<string> Parameter { get; internal set; }

        [DataMember(Name = "item_count")]
        public string ItemCount { get; internal set; }

        [DataMember(Name = "data_info")]
        public IEnumerable<string> DataInfo { get; internal set; }
    }
}
