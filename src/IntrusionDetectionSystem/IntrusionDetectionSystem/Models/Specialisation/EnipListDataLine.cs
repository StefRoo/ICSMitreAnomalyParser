using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class EnipListDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "device_type")]
        public string DeviceType { get; internal set; }

        [DataMember(Name = "vendor")]
        public string Vendor { get; internal set; }

        [DataMember(Name = "product_name")]
        public string ProductName { get; internal set; }

        [DataMember(Name = "serial_number")]
        public string SerialNumber { get; internal set; }

        [DataMember(Name = "product_code")]
        public string ProductCode { get; internal set; }

        [DataMember(Name = "revision")]
        public string Revision { get; internal set; }

        [DataMember(Name = "status")]
        public string Status { get; internal set; }

        [DataMember(Name = "state")]
        public string State { get; internal set; }

        [DataMember(Name = "device_ip")]
        public string DeviceIP { get; internal set; }
    }
}
