using System.Runtime.Serialization;

namespace IntrusionDetectionSystem.Models
{
    [DataContract]
    public class DataLine
    {
        [DataMember(Name = "ts")]
        public string TimeStamp { get; internal set; }

        [DataMember(Name = "uid")]
        public string Uid { get; internal set; }
    }
}
