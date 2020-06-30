using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class RdpDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "cookie")]
        public string Cookie { get; internal set; }

        [DataMember(Name = "result")]
        public string Result { get; internal set; }

        [DataMember(Name = "security_protocol")]
        public string SecurityProtocol { get; internal set; }

        [DataMember(Name = "client_channels")]
        public string ClientChannels { get; internal set; }

        [DataMember(Name = "keyboard_layout")]
        public string KeyboardLayout { get; internal set; }

        [DataMember(Name = "client_build")]
        public string ClientBuild { get; internal set; }

        [DataMember(Name = "client_name")]
        public string ClientName { get; internal set; }

        [DataMember(Name = "client_dig_product_id")]
        public string ClientDigProductId { get; internal set; }

        [DataMember(Name = "desktop_width")]
        public string DesktopWidth { get; internal set; }

        [DataMember(Name = "desktop_height")]
        public string DesktopHeight { get; internal set; }

        [DataMember(Name = "requested_color_depth")]
        public string RequestedColorDepth { get; internal set; }

        [DataMember(Name = "cert_type")]
        public string CertificateType { get; internal set; }

        [DataMember(Name = "cert_count")]
        public string CertificateCount { get; internal set; }

        [DataMember(Name = "cert_permanent")]
        public string IsCertificatePermanent { get; internal set; }

        [DataMember(Name = "encryption_level")]
        public string EncryptionLevel { get; internal set; }

        [DataMember(Name = "encryption_method")]
        public string EncryptionMethod { get; internal set; }
    }
}
