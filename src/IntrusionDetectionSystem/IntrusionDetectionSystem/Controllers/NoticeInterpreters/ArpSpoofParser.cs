using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace IntrusionDetectionSystem.Controllers
{
    public class ArpSpoofParser
    {
        public static (IcsMitreTechnique, IcsMitreTactic, string, string, string) ParseUnsolicitedReply(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            var firstNoticeLineValue = noticeLine.Value.FirstOrDefault();
            var noticeLineKey = noticeLine.Key;

            var match = Regex.Match(noticeLineKey.Message, "Source address: (.*). Destination address: (.*).");
            var originAddress = match.Groups[1].Value;
            var destAddress = match.Groups[2].Value;

            if (firstNoticeLineValue != null && decimal.TryParse(firstNoticeLineValue.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var result))
            {
                return (IcsMitreTechnique.ManInTheMiddle, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(result), originAddress, destAddress);
            }

            if (decimal.TryParse(noticeLineKey.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var keyResult))
            {
                return (IcsMitreTechnique.ManInTheMiddle, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(keyResult), originAddress, destAddress);
            }

            return (IcsMitreTechnique.ManInTheMiddle, IcsMitreTactic.Execution, string.Empty, originAddress, destAddress);
        }
    }
}