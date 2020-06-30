using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class MicroBrowserParser
    {
        public IEnumerable<(IcsMitreTechnique, IcsMitreTactic, string, string, string)> ParseHttpEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine, IEnumerable<DataLine> filesDataLines)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var httpLine = noticeLine.Value.Where(line => line is HttpDataLine).FirstOrDefault();
            if (!(httpLine is HttpDataLine httpDataLine))
            {
                return null;
            }

            if (string.IsNullOrEmpty(httpDataLine.HttpPostBody))
            {
                return null;
            }

            using (var ms = GenerateStreamFromString(httpDataLine.HttpPostBody))
            {
                // Reads the POST body into an XDocument to parse, grabbing the <action> element
                var body = XDocument.Load(ms);
                var actionTag = body.Descendants().
                    Where(element =>
                        element.Name.LocalName.Equals("action")).
                    FirstOrDefault();
                if (actionTag == null)
                {
                    return null;
                }

                var results = new List<(IcsMitreTechnique, IcsMitreTactic, string, string, string)>();

                // Matches the value of the action to its corresponding ICS MITRE techniques.
                // Proprietary protocol with (little to) no documentation, so only observed values 
                // are added to this switch
                switch (actionTag.Value)
                {
                    case "Read":
                        {
                            if (decimal.TryParse(httpLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var microBrowserReadResult))
                            {
                                var timeString = TimeConverter.UnixTimeToString(microBrowserReadResult);
                                results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, timeString, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                                results.Add((IcsMitreTechnique.DetectProgramState, IcsMitreTactic.Collection, timeString, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                                results.Add((IcsMitreTechnique.RoleIdentification, IcsMitreTactic.Collection, timeString, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                            }
                            else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeReadResult))
                            {
                                var timeString = TimeConverter.UnixTimeToString(noticeReadResult);
                                results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, timeString, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                                results.Add((IcsMitreTechnique.DetectProgramState, IcsMitreTactic.Collection, timeString, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                                results.Add((IcsMitreTechnique.RoleIdentification, IcsMitreTactic.Collection, timeString, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                            }
                            else
                            {
                                results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, string.Empty, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                                results.Add((IcsMitreTechnique.DetectProgramState, IcsMitreTactic.Collection, string.Empty, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                                results.Add((IcsMitreTechnique.RoleIdentification, IcsMitreTactic.Collection, string.Empty, httpDataLine.OriginAddress, httpDataLine.ResponderAddress));
                            }
                            break;
                        }
                    default:
                        break;
                }

                return results.Any() ? results : null;
            }
        }

        private Stream GenerateStreamFromString(string s)
        {
            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }
}