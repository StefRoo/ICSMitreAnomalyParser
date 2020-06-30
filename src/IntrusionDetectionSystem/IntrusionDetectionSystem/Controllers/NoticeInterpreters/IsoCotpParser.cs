using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class IsoCotpParser
    {
        private readonly S7CommParser _s7CommParser;

        public IsoCotpParser()
        {
            _s7CommParser = new S7CommParser();
        }

        public IEnumerable<(IcsMitreTechnique, IcsMitreTactic, string, string, string)> ParseCotpEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var isoCotpLine = noticeLine.Value.Where(line => line is IsoCotpDataLine).FirstOrDefault();
            if (!(isoCotpLine is IsoCotpDataLine isoCotpDataLine))
            {
                return null;
            }

            // ISO-COTP is the wrapper protocol for S7Comm data. Of all possible ISO-COTP
            // PDU types, only Data is interesting, and should be parsed by the S7Comm parser
            switch (isoCotpDataLine.PDUType)
            {
                case "Data":
                    return _s7CommParser.ParseS7CommEvent(noticeLine);
                case "Connect Request":
                case "Connect Confirm":
                default:
                    break;
            }

            return null;
        }
    }
}