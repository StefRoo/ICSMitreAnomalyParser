using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class HttpDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "trans_depth")]
        public string TransferDepth { get; internal set; }

        [DataMember(Name = "method")]
        public string Method { get; internal set; }

        [DataMember(Name = "host")]
        public string Host { get; internal set; }

        [DataMember(Name = "uri")]
        public string Uri { get; internal set; }

        [DataMember(Name = "referrer")]
        public string Referrer { get; internal set; }

        [DataMember(Name = "version")]
        public string Version { get; internal set; }

        [DataMember(Name = "user_agent")]
        public string UserAgent { get; internal set; }

        [DataMember(Name = "origin")]
        public string Origin { get; internal set; }

        [DataMember(Name = "request_body_len")]
        public string RequestBodyLength { get; internal set; }

        [DataMember(Name = "status_code")]
        public string StatusCode { get; internal set; }

        [DataMember(Name = "status_msg")]
        public string StatusMessage { get; internal set; }

        [DataMember(Name = "info_code")]
        public string InfoCode { get; internal set; }

        [DataMember(Name = "info_msg")]
        public string InfoMessage { get; internal set; }

        [DataMember(Name = "tags")]
        public string Tags { get; internal set; }

        [DataMember(Name = "username")]
        public string UserName { get; internal set; }

        [DataMember(Name = "password")]
        public string Password { get; internal set; }

        [DataMember(Name = "proxied")]
        public string Proxied { get; internal set; }

        [DataMember(Name = "orig_fuids")]
        public IEnumerable<string> OriginFileUids { get; internal set; }

        [DataMember(Name = "orig_filenames")]
        public IEnumerable<string> OriginFileNames { get; internal set; }

        [DataMember(Name = "orig_mime_types")]
        public IEnumerable<string> OriginMimeTypes { get; internal set; }

        [DataMember(Name = "resp_fuids")]
        public IEnumerable<string> ResponderFileUids { get; internal set; }

        [DataMember(Name = "resp_filenames")]
        public IEnumerable<string> ResponderFileNames { get; internal set; }

        [DataMember(Name = "resp_mime_types")]
        public IEnumerable<string> ResponderMimeTypes { get; internal set; }
        
        [DataMember(Name = "post_body")]
        public string HttpPostBody { get; internal set; }
    }
}
