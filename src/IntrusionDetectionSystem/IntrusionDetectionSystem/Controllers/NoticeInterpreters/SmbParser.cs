using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using IntrusionDetectionSystem.Models;

namespace IntrusionDetectionSystem.Controllers
{
    public class SmbParser
    {
        public (IcsMitreTechnique, IcsMitreTactic, string, string, string)? ParseSmb1Event(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var smbFileLine = noticeLine.Value.Where(line => line is SmbFilesDataLine).FirstOrDefault();
            if (!(smbFileLine is SmbFilesDataLine smbFilesDataLine))
            {
                return null;
            }

            switch (smbFilesDataLine.Action)
            {
                case "SMB::PIPE_WRITE":
                case "SMB::FILE_WRITE":
                case "SMB::PRINT_WRITE":
                    {
                        if (decimal.TryParse(smbFileLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var smbResult))
                        {
                            return (IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, TimeConverter.UnixTimeToString(smbResult), smbFilesDataLine.OriginAddress, smbFilesDataLine.ResponderAddress);
                        }

                        if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                        {
                            return (IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, TimeConverter.UnixTimeToString(noticeResult), smbFilesDataLine.OriginAddress, smbFilesDataLine.ResponderAddress);
                        }

                        return (IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, string.Empty, smbFilesDataLine.OriginAddress, smbFilesDataLine.ResponderAddress);
                    }
                default:
                    return null;
            }
        }

        public (IcsMitreTechnique, IcsMitreTactic, string, string, string)? ParseSmb2Event(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var smbFileLine = noticeLine.Value.Where(line => line is SmbFilesDataLine).FirstOrDefault();
            if (!(smbFileLine is SmbFilesDataLine smbFilesDataLine))
            {
                return null;
            }

            switch (smbFilesDataLine.Action)
            {
                case "SMB::PIPE_WRITE":
                case "SMB::FILE_WRITE":
                case "SMB::PRINT_WRITE":
                    {
                        if (decimal.TryParse(smbFileLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var smbResult))
                        {
                            return (IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, TimeConverter.UnixTimeToString(smbResult), smbFilesDataLine.OriginAddress, smbFilesDataLine.ResponderAddress);
                        }

                        if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                        {
                            return (IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, TimeConverter.UnixTimeToString(noticeResult), smbFilesDataLine.OriginAddress, smbFilesDataLine.ResponderAddress);
                        }

                        return (IcsMitreTechnique.RemoteFileCopy, IcsMitreTactic.LateralMovement, string.Empty, smbFilesDataLine.OriginAddress, smbFilesDataLine.ResponderAddress);
                    }
                default:
                    return null;
            }
        }
    }
}