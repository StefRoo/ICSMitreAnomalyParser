using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace IntrusionDetectionSystem.Controllers
{
    public class S7CommParser
    {
        public IEnumerable<(IcsMitreTechnique, IcsMitreTactic, string, string, string)> ParseS7CommEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var s7CommLine = noticeLine.Value.Where(line => line is S7CommDataLine).FirstOrDefault();
            if (!(s7CommLine is S7CommDataLine s7CommDataLine))
            {
                return null;
            }

            string actionType = null;
            foreach (var parameter in s7CommDataLine.Parameter)
            {
                // Loops over all the parameters in the S7Comm data, grabbing
                // either the type parameter or the sub parameter. Both represent
                // an S7Comm action, with the type parameter being a main action
                // and the sub parameter being a secondary (CPU) action. If either is found,
                // the loop is stopped.
                var typeMatch = Regex.Match(parameter, @"type=(.+)");
                var subMatch = Regex.Match(parameter, @"sub=(.+)");
                if (typeMatch.Success)
                {
                    actionType = typeMatch.Groups[1].Value;
                    break;
                }
                else if (subMatch.Success)
                {
                    actionType = subMatch.Groups[1].Value;
                    break;
                }
            }

            var results = new List<(IcsMitreTechnique, IcsMitreTactic, string, string, string)>();

            // Matches the S7Comm action to the corresponding techniques, based on the ICS MITRE framework
            switch (actionType)
            {
                case "Read Variable":
                    {
                        if (decimal.TryParse(s7CommLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var s7CommReadResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(s7CommReadResult);
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.DetectProgramState, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.RoleIdentification, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeReadResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(noticeReadResult);
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.DetectProgramState, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.RoleIdentification, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.DetectProgramState, IcsMitreTactic.Collection, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.RoleIdentification, IcsMitreTactic.Collection, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        break;
                    }
                case "PI Service":
                case "PLC Control":
                case "PLC Stop":
                    {
                        if (decimal.TryParse(s7CommLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var s7CommChangeModeResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(s7CommChangeModeResult);
                            results.Add((IcsMitreTechnique.EvasionUtilizeOrChangeOperatingMode, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.InhibitResponseFunctionUtilizeOrChangeOperatingMode, IcsMitreTactic.ImpairProcessControl, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeChangeModeResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(noticeChangeModeResult);
                            results.Add((IcsMitreTechnique.EvasionUtilizeOrChangeOperatingMode, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.InhibitResponseFunctionUtilizeOrChangeOperatingMode, IcsMitreTactic.ImpairProcessControl, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.EvasionUtilizeOrChangeOperatingMode, IcsMitreTactic.Collection, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.InhibitResponseFunctionUtilizeOrChangeOperatingMode, IcsMitreTactic.ImpairProcessControl, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        break;
                    }
                case "Write Variable":
                    {
                        if (decimal.TryParse(s7CommLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var s7CommWriteResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(s7CommWriteResult);
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeWriteResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(noticeWriteResult);
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        break;
                    }
                case "Request Download":
                case "Download Block":
                case "Download Ended":
                    {
                        if (decimal.TryParse(s7CommLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var s7CommDownloadResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(s7CommDownloadResult);
                            results.Add((IcsMitreTechnique.PersistenceProgramDownload, IcsMitreTactic.Persistence, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.InhibitResponseFunctionProgramDownload, IcsMitreTactic.InhibitResponseFunction, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlProgramDownload, IcsMitreTactic.ImpairProcessControl, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeDownloadResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(noticeDownloadResult);
                            results.Add((IcsMitreTechnique.PersistenceProgramDownload, IcsMitreTactic.Persistence, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.InhibitResponseFunctionProgramDownload, IcsMitreTactic.InhibitResponseFunction, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlProgramDownload, IcsMitreTactic.ImpairProcessControl, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.PersistenceProgramDownload, IcsMitreTactic.Persistence, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.InhibitResponseFunctionProgramDownload, IcsMitreTactic.InhibitResponseFunction, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlProgramDownload, IcsMitreTactic.ImpairProcessControl, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        break;
                    }
                case "Start Upload":
                case "Upload":
                case "End Upload":
                    {
                        if (decimal.TryParse(s7CommLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var s7CommUploadResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(s7CommUploadResult);
                            results.Add((IcsMitreTechnique.ProgramUpload, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeUploadResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(noticeUploadResult);
                            results.Add((IcsMitreTechnique.ProgramUpload, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.ProgramUpload, IcsMitreTactic.Collection, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        break;
                    }
                case "Read SZL":
                    {
                        if (decimal.TryParse(s7CommLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var s7CommReadSZLResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(s7CommReadSZLResult);
                            results.Add((IcsMitreTechnique.DetectOperatingMode, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeReadSZLResult))
                        {
                            var timeString = TimeConverter.UnixTimeToString(noticeReadSZLResult);
                            results.Add((IcsMitreTechnique.DetectOperatingMode, IcsMitreTactic.Collection, timeString, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.DetectOperatingMode, IcsMitreTactic.Collection, string.Empty, s7CommDataLine.OriginAddress, s7CommDataLine.ResponderAddress));
                        }
                        break;
                    }
                case "CPU Services":
                case "Setup Communication":
                default:
                    break;
            }

            return results.Any() ? results : null;
        }
    }
}