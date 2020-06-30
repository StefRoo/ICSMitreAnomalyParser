using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class X509DataLine : DataLine
    {
        [DataMember(Name = "id")]
        public string Id { get; internal set; }

        [DataMember(Name = "certificate.version")]
        public string CertificateVersion { get; internal set; }

        [DataMember(Name = "certificate.serial")]
        public string CertificateSerial { get; internal set; }

        [DataMember(Name = "certificate.subject")]
        public string CertificateSubject { get; internal set; }

        [DataMember(Name = "certificate.issuer")]
        public string CertificateIssuer { get; internal set; }

        [DataMember(Name = "certificate.not_valid_before")]
        public string CertificateNotValidBefore { get; internal set; }

        [DataMember(Name = "certificate.not_valid_after")]
        public string CertificateNotValidAfter { get; internal set; }

        [DataMember(Name = "certificate.key_alg")]
        public string CertificateKeyAlgorithm { get; internal set; }

        [DataMember(Name = "certificate.sig_alg")]
        public string CertificateSignatureAlgorithm { get; internal set; }

        [DataMember(Name = "certificate.key_type")]
        public string CertificateKeyType { get; internal set; }

        [DataMember(Name = "ccertificate.key_length")]
        public string CertificateKeyLength { get; internal set; }

        [DataMember(Name = "certificate.exponent")]
        public string CertificateExponent { get; internal set; }

        [DataMember(Name = "certificate.curve")]
        public string CertificateCurve { get; internal set; }

        [DataMember(Name = "san.dns")]
        public IEnumerable<string> SanDns { get; internal set; }

        [DataMember(Name = "san.uri")]
        public IEnumerable<string> SanUri { get; internal set; }

        [DataMember(Name = "san.email")]
        public IEnumerable<string> SanEmail { get; internal set; }

        [DataMember(Name = "san.ip")]
        public IEnumerable<string> SanIp { get; internal set; }

        [DataMember(Name = "basic_constraints.ca")]
        public string BasicConstraintsCa { get; internal set; }

        [DataMember(Name = "basic_constraints.path_len")]
        public string BasicConstraintsPathLength { get; internal set; }
    }
}
