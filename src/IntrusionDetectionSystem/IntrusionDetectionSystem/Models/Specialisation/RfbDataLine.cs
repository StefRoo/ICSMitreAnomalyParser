using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class RfbDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "client_major_version")]
        public string ClientMajorVersion { get; internal set; }

        [DataMember(Name = "client_minor_version")]
        public string ClientMinorVersion { get; internal set; }

        [DataMember(Name = "server_major_version")]
        public string ServerMajorVersion { get; internal set; }

        [DataMember(Name = "server_minor_version")]
        public string ServerMinorVersion { get; internal set; }

        [DataMember(Name = "authentication_method")]
        public string AuthenticationMethod { get; internal set; }

        [DataMember(Name = "auth")]
        public string IsAuthorized { get; internal set; }

        [DataMember(Name = "share_flag")]
        public string HasShareFlag { get; internal set; }

        [DataMember(Name = "desktop_name")]
        public string DesktopName { get; internal set; }

        [DataMember(Name = "width")]
        public string Width { get; internal set; }

        [DataMember(Name = "height")]
        public string Height { get; internal set; }
    }
}
