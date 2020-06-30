using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class SmtpDataLine : DataLine
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

        [DataMember(Name = "helo")]
        public string Helo { get; internal set; }

        [DataMember(Name = "mailfrom")]
        public string MailFrom { get; internal set; }

        [DataMember(Name = "rcptto")]
        public IEnumerable<string> RcptTo { get; internal set; }

        [DataMember(Name = "date")]
        public string Date { get; internal set; }

        [DataMember(Name = "from")]
        public string From { get; internal set; }

        [DataMember(Name = "to")]
        public IEnumerable<string> To { get; internal set; }

        [DataMember(Name = "cc")]
        public IEnumerable<string> CC { get; internal set; }

        [DataMember(Name = "reply_to")]
        public string ReplyTo { get; internal set; }

        [DataMember(Name = "msg_id")]
        public string MessageId { get; internal set; }

        [DataMember(Name = "in_reply_to")]
        public string InReplyTo { get; internal set; }

        [DataMember(Name = "subject")]
        public string Subject { get; internal set; }

        [DataMember(Name = "x_origination_ip")]
        public string XOriginatingIp { get; internal set; }

        [DataMember(Name = "first_received")]
        public string FirstReceived { get; internal set; }

        [DataMember(Name = "second_received")]
        public string SecondReceived { get; internal set; }

        [DataMember(Name = "last_reply")]
        public string LastReply { get; internal set; }

        [DataMember(Name = "path")]
        public IEnumerable<string> Path { get; internal set; }

        [DataMember(Name = "user_agent")]
        public string UserAgent { get; internal set; }

        [DataMember(Name = "tls")]
        public string HasTls { get; internal set; }

        [DataMember(Name = "fuids")]
        public IEnumerable<string> FileUids { get; internal set; }
    }
}
