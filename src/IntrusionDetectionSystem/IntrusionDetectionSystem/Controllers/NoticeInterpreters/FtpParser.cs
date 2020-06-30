using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class FtpParser
    {
        public IEnumerable<(IcsMitreTechnique, IcsMitreTactic, string, string, string)> ParsePEEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var ftpLine = noticeLine.Value.Where(line => line is FtpDataLine).FirstOrDefault();
            if (!(ftpLine is FtpDataLine ftpDataLine))
            {
                return null;
            }

            var results = new List<(IcsMitreTechnique, IcsMitreTactic, string, string, string)>();

            // Checks for the use of default FTP credentials (user: Anonymous, password: anonymous)
            if (string.Equals(ftpDataLine.User, "Anonymous") && string.Equals(ftpDataLine.Password, "anonymous"))
            {
                if (decimal.TryParse(ftpLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var ftpResult))
                {
                    var timeString = TimeConverter.UnixTimeToString(ftpResult);
                    results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.DefaultCredentials, IcsMitreTactic.LateralMovement, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                }
                else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                {
                    var timeString = TimeConverter.UnixTimeToString(noticeResult);
                    results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.DefaultCredentials, IcsMitreTactic.LateralMovement, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                }
                else
                {
                    results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.DefaultCredentials, IcsMitreTactic.LateralMovement, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                }
            }
            else
            {
                if (decimal.TryParse(ftpLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var ftpResult))
                {
                    var timeString = TimeConverter.UnixTimeToString(ftpResult);
                    results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                }
                else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                {
                    var timeString = TimeConverter.UnixTimeToString(noticeResult);
                    results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, timeString, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                }
                else
                {
                    results.Add((IcsMitreTechnique.PersistenceModuleFirmware, IcsMitreTactic.Persistence, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.ImpairProcessControlModuleFirmware, IcsMitreTactic.ImpairProcessControl, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.PersistenceSystemFirmware, IcsMitreTactic.Persistence, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.InhibitResponseFunctionSystemFirmware, IcsMitreTactic.InhibitResponseFunction, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                    results.Add((IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, string.Empty, ftpDataLine.OriginAddress, ftpDataLine.ResponderAddress));
                }
            }

            return results.Any() ? results : null;
        }
    }
}