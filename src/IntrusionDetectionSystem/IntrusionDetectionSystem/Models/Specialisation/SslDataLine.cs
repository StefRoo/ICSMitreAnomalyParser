using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class SslDataLine : DataLine
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

        [DataMember(Name = "cipher")]
        public string Cipher { get; internal set; }

        [DataMember(Name = "curve")]
        public string Curve { get; internal set; }

        [DataMember(Name = "server_name")]
        public string ServerName { get; internal set; }

        [DataMember(Name = "resumed")]
        public string IsResumed { get; internal set; }

        [DataMember(Name = "last_alert")]
        public string LastAlert { get; internal set; }

        [DataMember(Name = "next_protocol")]
        public string NextProtocol { get; internal set; }

        [DataMember(Name = "established")]
        public string IsEstablished { get; internal set; }

        [DataMember(Name = "cert_chain_fuids")]
        public IEnumerable<string> CertificateChainFileUids { get; internal set; }

        [DataMember(Name = "client_cert_chain_fuids")]
        public IEnumerable<string> ClientCertificateChainFileUids { get; internal set; }

        [DataMember(Name = "subject")]
        public string Subject { get; internal set; }

        [DataMember(Name = "issuer")]
        public string Issuer { get; internal set; }

        [DataMember(Name = "client_subject")]
        public string ClientSubject { get; internal set; }

        [DataMember(Name = "client_issuer")]
        public string ClientIssuer { get; internal set; }
    }
}
