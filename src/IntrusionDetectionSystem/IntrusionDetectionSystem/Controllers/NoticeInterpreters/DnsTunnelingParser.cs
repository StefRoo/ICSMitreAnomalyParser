using IntrusionDetectionSystem.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class DnsTunnelingParser
    {
        private readonly List<string> _timeStamps;

        public DnsTunnelingParser()
        {
            _timeStamps = new List<string>();
        }

        public (IcsMitreTechnique, IcsMitreTactic, string, string, string)? ParseDnsTunnel(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var dnsLine = noticeLine.Value.Where(line => line is DnsDataLine).FirstOrDefault();
            if (!(dnsLine is DnsDataLine dnsDataLine))
            {
                return null;
            }

            // Calculates the Shannon entropy over the DNS query. If
            // the entropy is higher than 4, it gets marked as an anomaly.
            // This is on the higher end of normal (english) text.
            var query = dnsDataLine.Query;
            if (ShannonEntropy(query) > 4.0)
            {
                _timeStamps.Add(dnsDataLine.TimeStamp);
            }

            if (_timeStamps.Count < 2)
            {
                return null;
            }

            if (!(decimal.TryParse(_timeStamps.First(), NumberStyles.Any, CultureInfo.InvariantCulture, out var firstTimeStamp) && decimal.TryParse(_timeStamps.Last(), NumberStyles.Any, CultureInfo.InvariantCulture, out var lastTimeStamp)))
            {
                _timeStamps.Clear();
                return null;
            }

            // Calculates the difference between the first and the last timestamps
            // that were marked as anomalies
            var difference = lastTimeStamp - firstTimeStamp;

            if (lastTimeStamp - firstTimeStamp > 30)
            {
                // If the difference is higher than 30 seconds, the timestamps get cleared
                _timeStamps.Clear();
                return null;
            }
            else if (_timeStamps.Count > 15)
            {
                // Otherwise, if at least 16 anomalies have been spotted in 30 seconds,
                // the decision gets made that this is a DNS tunnel. So that means:
                //     - At least 16 queries
                //         - Length > 52
                //         - Shannon entropy > 4
                //     - Within 30 seconds
                _timeStamps.Clear();
                return (IcsMitreTechnique.ConnectionProxy, IcsMitreTactic.CommandAndControl, TimeConverter.UnixTimeToString(firstTimeStamp), dnsDataLine.OriginAddress, dnsDataLine.ResponderAddress);
            }
            return null;
        }

        /// <summary>
        /// Returns bits of entropy represented in a given string, per 
        /// http://en.wikipedia.org/wiki/Entropy_(information_theory) 
        /// </summary>
        private static double ShannonEntropy(string s)
        {
            var map = new Dictionary<char, int>();
            foreach (var c in s)
            {
                if (!map.ContainsKey(c))
                {
                    map.Add(c, 1);
                }
                else
                {
                    map[c] += 1;
                }
            }

            var result = 0.0;
            var len = s.Length;
            foreach (var item in map)
            {
                var frequency = (double)item.Value / len;
                result -= frequency * (Math.Log(frequency) / Math.Log(2));
            }

            return result;
        }
    }
}