using IntrusionDetectionSystem.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class SshParser
    {
        private List<(string, int)> _loginAttempts;

        public SshParser()
        {
            _loginAttempts = new List<(string, int)>();
        }

        public (IcsMitreTechnique, IcsMitreTactic, string, string, string)? ParseSSHEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var sshLine = noticeLine.Value.Where(line => line is SshDataLine).FirstOrDefault();
            if (!(sshLine is SshDataLine sshDataLine))
            {
                return null;
            }

            if (!decimal.TryParse(sshDataLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var timeStamp))
            {
                return null;
            }

            var dateTime = TimeConverter.UnixTimeToDateTime(timeStamp);

            // An easy check is on office hours. If the connection has been done in the weekend
            // or outside of 7AM-7PM, it is immediately marked as suspicious.
            if (dateTime.DayOfWeek == DayOfWeek.Saturday || dateTime.DayOfWeek == DayOfWeek.Sunday)
            {
                if (decimal.TryParse(sshLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var sshResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(sshResult), sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                }
                else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeResult), sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                }
                else
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, string.Empty, sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                }
            }
            else if (dateTime.Hour < 7 || dateTime.Hour > 19)
            {
                if (decimal.TryParse(sshLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var sshResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(sshResult), sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                }
                else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeResult), sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                }
                else
                {
                    return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, string.Empty, sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                }
            }

            // Adds the login attempt to a list of login attempts
            switch (noticeLine.Key.NoticeType)
            {
                case "SecureShell::SshFailure":
                    _loginAttempts.Add((sshDataLine.ResponderAddress, 0));
                    break;
                case "SecureShell::SshSuccess":
                    _loginAttempts.Add((sshDataLine.ResponderAddress, 1));
                    break;
                default:
                    break;
            }

            // Gets all login attempts for the same host, and gets the successful attempts from those attempts
            var attemptsForCurrentHost = _loginAttempts.Where(attempt => attempt.Item1.Equals(sshDataLine.ResponderAddress));
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
                    if (decimal.TryParse(sshLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var sshResult))
                    {
                        return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(sshResult), sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                    }
                    else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
                    {
                        return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeResult), sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
                    }
                    else
                    {
                        return (IcsMitreTechnique.CommandLineInterface, IcsMitreTactic.Execution, string.Empty, sshDataLine.OriginAddress, sshDataLine.ResponderAddress);
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