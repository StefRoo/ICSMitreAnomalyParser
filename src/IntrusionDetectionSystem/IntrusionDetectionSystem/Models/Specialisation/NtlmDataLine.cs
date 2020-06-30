using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class NtlmDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "username")]
        public string UserName { get; internal set; }

        [DataMember(Name = "hostname")]
        public string HostName { get; internal set; }

        [DataMember(Name = "domainname")]
        public string DomainName { get; internal set; }

        [DataMember(Name = "server_nb_computer_name")]
        public string ServerNBComputerName { get; internal set; }

        [DataMember(Name = "server_dns_computer_name")]
        public string ServerDnsComputerName { get; internal set; }

        [DataMember(Name = "server_tree_name")]
        public string ServerTreeName { get; internal set; }

        [DataMember(Name = "success")]
        public string IsSuccess { get; internal set; }
    }
}
