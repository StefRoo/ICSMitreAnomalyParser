using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace IntrusionDetectionSystem.Controllers
{
    public static class ScanDetectionParser
    {
        public static (IcsMitreTechnique, IcsMitreTactic, string, string, string) ParsePortScanSummary(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            var firstNoticeLineValue = noticeLine.Value.FirstOrDefault();
            var noticeLineKey = noticeLine.Key;

            var match = Regex.Match(noticeLineKey.Message, "(.*) scanned");
            var originAddress = match.Groups[1].Value;

            // Any detected TCP scan by Zeek is an anomaly, so should always be mapped to a technique.
            // The network service scanning technique is not returned with a destination address,
            // as obviously, there are multiple destinations for a network service scan.
            if (firstNoticeLineValue != null && decimal.TryParse(firstNoticeLineValue.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var result))
            {
                return (IcsMitreTechnique.NetworkServiceScanning, IcsMitreTactic.Discovery, TimeConverter.UnixTimeToString(result), originAddress, string.Empty);
            }
            else if (decimal.TryParse(noticeLineKey.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var keyResult))
            {
                return (IcsMitreTechnique.NetworkServiceScanning, IcsMitreTactic.Discovery, TimeConverter.UnixTimeToString(keyResult), originAddress, string.Empty);
            }
            return (IcsMitreTechnique.NetworkServiceScanning, IcsMitreTactic.Discovery, string.Empty, originAddress, string.Empty);
        }
    }
}