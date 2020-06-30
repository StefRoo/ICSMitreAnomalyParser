using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class FtpDataLine : DataLine
    {
        [DataMember(Name = "id.orig_h")]
        public string OriginAddress { get; internal set; }

        [DataMember(Name = "id.orig_p")]
        public string OriginPort { get; internal set; }

        [DataMember(Name = "id.resp_h")]
        public string ResponderAddress { get; internal set; }

        [DataMember(Name = "id.resp_p")]
        public string ResponderPort { get; internal set; }

        [DataMember(Name = "user")]
        public string User { get; internal set; }

        [DataMember(Name = "password")]
        public string Password { get; internal set; }

        [DataMember(Name = "command")]
        public string Command { get; internal set; }

        [DataMember(Name = "arg")]
        public string Arguments { get; internal set; }

        [DataMember(Name = "mime_type")]
        public string MimeType { get; internal set; }

        [DataMember(Name = "file_size")]
        public string FileSize { get; internal set; }

        [DataMember(Name = "reply_code")]
        public string ReplyCode { get; internal set; }

        [DataMember(Name = "reply_msg")]
        public string ReplyMessage { get; internal set; }

        [DataMember(Name = "data_channel.passive")]
        public string DataChannelIsPassive { get; internal set; }

        [DataMember(Name = "data_channel.orig_h")]
        public string DataChannelOriginAddress { get; internal set; }

        [DataMember(Name = "data_channel.resp_h")]
        public string DataChannelResponderAddress { get; internal set; }

        [DataMember(Name = "data_channel.resp_p")]
        public string DataChannelResponderPort{ get; internal set; }

        [DataMember(Name = "fuid")]
        public string FileUid { get; internal set; }
    }
}
