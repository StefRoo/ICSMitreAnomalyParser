using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class ProfinetDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "operation_type")]
        public string OperationType { get; internal set; }

        [DataMember(Name = "block_version")]
        public string BlockVersion { get; internal set; }

        [DataMember(Name = "slot_number")]
        public string SlotNumber { get; internal set; }

        [DataMember(Name = "subslot_number")]
        public string SubSlotNumber { get; internal set; }

        [DataMember(Name = "index")]
        public string Index { get; internal set; }
    }
}
