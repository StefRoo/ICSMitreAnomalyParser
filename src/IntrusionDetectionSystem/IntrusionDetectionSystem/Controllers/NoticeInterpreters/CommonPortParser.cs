using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using IntrusionDetectionSystem.Models;

namespace IntrusionDetectionSystem.Controllers
{
    public class CommonPortParser
    {
        private static readonly List<string> _commonPorts = new List<string>
        {
            "80",
            "8080",
            "443",
            "53",
            "5353",
            "23",
            "161",
            "502",
            "22",
            "102",
            "20000",
            "44818"
        };

        public (IcsMitreTechnique, IcsMitreTactic, string, string, string)? ParseCommonPort(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var connLine = noticeLine.Value.Where(line => line is ConnDataLine).FirstOrDefault();
            if (!(connLine is ConnDataLine connDataLine))
            {
                return null;
            }

            if (_commonPorts.Contains(connDataLine.OriginPort))
            {
                return CheckProtocol(connDataLine.OriginPort, connDataLine, noticeLine.Key);
            }
            else if (_commonPorts.Contains(connDataLine.ResponderPort))
            {
                return CheckProtocol(connDataLine.ResponderPort, connDataLine, noticeLine.Key);
            }

            return null;
        }

        private (IcsMitreTechnique, IcsMitreTactic, string, string, string)? CheckProtocol(string port, ConnDataLine connDataLine, NoticeDataLine key)
        {
            switch (port)
            {
                case "80":
                case "8080":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "http"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "443":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "ssl"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "53":
                case "5353":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "dns"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "23":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "telnet"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "161":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "snmp"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "502":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "modbus"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "22":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "ssh"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "102":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "s7comm"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }                    
                case "20000":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "dnp3"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                case "44818":
                    {
                        if (!string.IsNullOrEmpty(connDataLine.ServiceProtocol) && !string.Equals(connDataLine.ServiceProtocol, "ethernet/ip"))
                        {
                            return ConstructTechnique(connDataLine, key);
                        }
                        return null;
                    }
                default:
                    return null;
            }
        }

        private (IcsMitreTechnique, IcsMitreTactic, string, string, string)? ConstructTechnique(ConnDataLine connDataLine, NoticeDataLine key)
        {
            if (decimal.TryParse(connDataLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var dnsResult))
            {
                return (IcsMitreTechnique.CommonlyUsedPort, IcsMitreTactic.CommandAndControl, TimeConverter.UnixTimeToString(dnsResult), connDataLine.OriginAddress, connDataLine.ResponderAddress);
            }

            if (decimal.TryParse(key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeResult))
            {
                return (IcsMitreTechnique.CommonlyUsedPort, IcsMitreTactic.CommandAndControl, TimeConverter.UnixTimeToString(noticeResult), connDataLine.OriginAddress, connDataLine.ResponderAddress);
            }

            return (IcsMitreTechnique.CommonlyUsedPort, IcsMitreTactic.CommandAndControl, string.Empty, connDataLine.OriginAddress, connDataLine.ResponderAddress);
        }
    }
}