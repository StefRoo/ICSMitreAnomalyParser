using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class SshDataLine : DataLine
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

        [DataMember(Name = "auth_success")]
        public string AuthenticationIsSuccessful { get; internal set; }

        [DataMember(Name = "auth_attempts")]
        public string AuthenticationAttempts { get; internal set; }

        [DataMember(Name = "direction")]
        public string Direction { get; internal set; }

        [DataMember(Name = "client")]
        public string Client { get; internal set; }

        [DataMember(Name = "server")]
        public string Server { get; internal set; }

        [DataMember(Name = "cipher_alg")]
        public string CipherAlgorithm { get; internal set; }

        [DataMember(Name = "mac_alg")]
        public string SigningAlgorithm { get; internal set; }

        [DataMember(Name = "compression_alg")]
        public string CompressionAlgorithm { get; internal set; }

        [DataMember(Name = "kex_alg")]
        public string KeyExchangeAlgorithm { get; internal set; }

        [DataMember(Name = "host_key_alg")]
        public string HostKeyAlgorithm { get; internal set; }

        [DataMember(Name = "host_key")]
        public string HostKey { get; internal set; }
    }
}
