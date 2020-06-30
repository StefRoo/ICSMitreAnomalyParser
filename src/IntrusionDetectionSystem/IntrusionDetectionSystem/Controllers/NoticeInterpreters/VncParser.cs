using IntrusionDetectionSystem.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class VncParser
    {
        private List<(string, int)> _loginAttempts;

        public VncParser()
        {
            _loginAttempts = new List<(string, int)>();
        }

        public (IcsMitreTechnique, IcsMitreTactic, string, string, string)? ParseVNCEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var vncLine = noticeLine.Value.Where(line => line is RfbDataLine).FirstOrDefault();
            if (!(vncLine is RfbDataLine vncDataLine))
            {
                return null;
            }

            if (!decimal.TryParse(vncDataLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var timeStamp))
            {
                return null;
            }

            var dateTime = TimeConverter.UnixTimeToDateTime(timeStamp);

            // An easy check is on office hours. If the connection has been done in the weekend
            // or outside of 7AM-7PM, it is immediately marked as suspicious.
            if (dateTime.DayOfWeek == DayOfWeek.Saturday || dateTime.DayOfWeek == DayOfWeek.Sunday)
            {
                if (decimal.TryParse(vncLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var vncResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(vncResult), vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                }
                else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeResult), vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                }
                else
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, string.Empty, vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                }
            }
            else if (dateTime.Hour < 7 || dateTime.Hour > 19)
            {
                if (decimal.TryParse(vncLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var vncResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(vncResult), vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                }
                else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeResult), vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                }
                else
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, string.Empty, vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                }
            }

            // Adds the login attempt to a list of login attempts
            switch (noticeLine.Key.NoticeType)
            {
                case "VNC::VNCFailure":
                    _loginAttempts.Add((vncDataLine.ResponderAddress, 0));
                    break;
                case "VNC::VNCSuccess":
                    _loginAttempts.Add((vncDataLine.ResponderAddress, 1));
                    break;
                default:
                    break;
            }

            // Gets all login attempts for the same host, and gets the successful attempts from those attempts
            var attemptsForCurrentHost = _loginAttempts.Where(attempt => attempt.Item1.Equals(vncDataLine.ResponderAddress));
            var successfulAttempts = attemptsForCurrentHost.Where(attempt => attempt.Item2 == 1);

            if (successfulAttempts.Count() > 0)
            {
                // If there is at least one successful attempt, all unsuccessful attemps are counted
                var unsuccessfulAttempts = attemptsForCurrentHost.Where(attempt => attempt.Item2 == 0);
                if (unsuccessfulAttempts.Count() > 2)
                {
                    // If the amount of unsuccessful attempts is 3 or higher, it triggers a technique
                    // and the attempts for the current host get removed from the login attempts
                    _loginAttempts = _loginAttempts.Except(attemptsForCurrentHost).ToList();
                    if (decimal.TryParse(vncLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var vncResult))
                    {
                        return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(vncResult), vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                    }
                    else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                    {
                        return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeResult), vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                    }
                    else
                    {
                        return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, string.Empty, vncDataLine.OriginAddress, vncDataLine.ResponderAddress);
                    }
                }

                // If the amount of unsuccessful attempts is 2 or lower, the attempts for the current host get 
                // removed regardless as it did not trigger a technique.
                _loginAttempts = _loginAttempts.Except(attemptsForCurrentHost).ToList();
            }

            return null;
        }
    }
}