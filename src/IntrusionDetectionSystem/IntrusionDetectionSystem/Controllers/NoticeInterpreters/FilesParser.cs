using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class FilesParser
    {
        public IEnumerable<(IcsMitreTechnique, IcsMitreTactic, string, string, string)> ParsePEEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var filesLine = noticeLine.Value.Where(line => line is FilesDataLine).FirstOrDefault();
            if (!(filesLine is FilesDataLine filesDataLine))
            {
                return null;
            }

            var results = new List<(IcsMitreTechnique, IcsMitreTactic, string, string, string)>();

            if (decimal.TryParse(filesLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var filesResult))
            {
                var timeString = TimeConverter.UnixTimeToString(filesResult);
                results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, timeString, string.Empty, string.Empty));
            }
            else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
            {
                var timeString = TimeConverter.UnixTimeToString(noticeResult);
                results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, timeString, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, timeString, string.Empty, string.Empty));
            }
            else
            {
                results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, string.Empty, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, string.Empty, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, string.Empty, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, string.Empty, string.Empty, string.Empty));
                results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, string.Empty, string.Empty, string.Empty));
            }

            return results.Any() ? results : null;
        }
    }
}