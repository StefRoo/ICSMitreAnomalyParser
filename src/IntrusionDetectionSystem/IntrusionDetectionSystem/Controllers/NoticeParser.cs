using IntrusionDetectionSystem.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class NoticeParser
    {
        private readonly DnsTunnelingParser _tunnelingParser;
        private readonly ModbusParser _modbusParser;
        private readonly IsoCotpParser _isoCotpParser;
        private readonly S7CommParser _s7CommParser;
        private readonly FtpParser _ftpParser;
        private readonly SmbParser _smbParser;
        private readonly CommonPortParser _commonPortParser;
        private readonly RdpParser _rdpParser;
        private readonly SshParser _sshParser;
        private readonly VncParser _vncParser;
        private readonly TelnetParser _telnetParser;
        private readonly FilesParser _filesParser;
        private readonly MicroBrowserParser _microBrowserParser;

        public NoticeParser()
        {
            _tunnelingParser = new DnsTunnelingParser();
            _modbusParser = new ModbusParser();
            _isoCotpParser = new IsoCotpParser();
            _s7CommParser = new S7CommParser();
            _ftpParser = new FtpParser();
            _smbParser = new SmbParser();
            _commonPortParser = new CommonPortParser();
            _rdpParser = new RdpParser();
            _sshParser = new SshParser();
            _vncParser = new VncParser();
            _telnetParser = new TelnetParser();
            _filesParser = new FilesParser();
            _microBrowserParser = new MicroBrowserParser();
        }

        public IEnumerable<(IcsMitreTechnique, IcsMitreTactic, string, string, string)> ParseNotices(IDictionary<NoticeDataLine, IEnumerable<DataLine>> noticeDictionary, IEnumerable<DataLine> filesDataLines)
        {
            var results = new List<(IcsMitreTechnique, IcsMitreTactic, string, string, string)>();

            // Loops through the notices and their corresponding DataLine objects,
            // adding any results to the list
            foreach (var noticeLine in noticeDictionary)
            {
                switch (noticeLine.Key.NoticeType)
                {
                    case "CommonPorts::Common_Port":
                        {
                            if (_commonPortParser.ParseCommonPort(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> commonPortResult)
                            {
                                results.Add(commonPortResult);
                            }
                            break;
                        }
                    case "DNS_TUNNELS::OversizedQuery":
                        {
                            if (_tunnelingParser.ParseDnsTunnel(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> dnsTunnelResult)
                            {
                                results.Add(dnsTunnelResult);
                            }
                            break;
                        }
                    case "DNSSpoof::DNSCachePoisoning":
                        break;
                    case "Scan::Port_Scan":
                    case "Scan::Address_Scan":
                        {
                            var scanDetectionResult = ScanDetectionParser.ParsePortScanSummary(noticeLine);
                            results.Add(scanDetectionResult);
                            break;
                        }
                    case "HTTP_USER_AGENT::MicroBrowser":
                        {
                            if (_microBrowserParser.ParseHttpEvent(noticeLine, filesDataLines) is IEnumerable<ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string>> httpResult)
                            {
                                foreach (var result in httpResult)
                                {
                                    results.Add(result);
                                }
                            }
                            break;
                        }
                    case "ModbusLogging::ModbusEvent":
                        {
                            if (_modbusParser.ParseModbusEvent(noticeLine) is IEnumerable<ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string>> modbusResult)
                            {
                                foreach (var result in modbusResult)
                                {
                                    results.Add(result);
                                }
                            }
                            break;
                        }
                    case "SMB_LOGGING::SMB1Command":
                        {
                            if (_smbParser.ParseSmb1Event(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> smb1Result)
                            {
                                results.Add(smb1Result);
                            }
                            break;
                        }
                    case "SMB_LOGGING::SMB2Command":
                        {
                            if (_smbParser.ParseSmb2Event(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> smb2Result)
                            {
                                results.Add(smb2Result);
                            }
                            break;
                        }
                    case "RDPDetection::RDPSuccess":
                    case "RDPDetectuib::RDPFailure":
                        {
                            if (_rdpParser.ParseRDPEvent(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> rdpResult)
                            {
                                results.Add(rdpResult);
                            }
                            break;
                        }
                    case "SecureShell::SshSuccess":
                    case "SecureShell::SshFailure":
                        {
                            if (_sshParser.ParseSSHEvent(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> sshResult)
                            {
                                results.Add(sshResult);
                            }
                            break;
                        }
                    case "VNC::VNCSuccess":
                    case "VNC::VNCFailure":
                        {
                            if (_vncParser.ParseVNCEvent(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> vncResult)
                            {
                                results.Add(vncResult);
                            }
                            break;
                        }
                    case "TelnetShell::LoginSuccess":
                    case "TelnetShell::LoginFailure":
                        {
                            if (_telnetParser.ParseTelnetEvent(noticeLine) is ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string> telnetResult)
                            {
                                results.Add(telnetResult);
                            }
                            break;
                        }
                    case "S7CommLogging::IsoCotp":
                        {
                            if (_isoCotpParser.ParseCotpEvent(noticeLine) is IEnumerable<ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string>> isoCotpResult)
                            {
                                foreach (var result in isoCotpResult)
                                {
                                    results.Add(result);
                                }

                            }
                            break;
                        }
                    case "S7CommLogging::S7CommData":
                        {
                            if (_s7CommParser.ParseS7CommEvent(noticeLine) is IEnumerable<ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string>> s7CommResult)
                            {
                                foreach (var result in s7CommResult)
                                {
                                    results.Add(result);
                                }
                            }
                            break;
                        }
                    case "PortableExecutables::FtpPE":
                        {
                            if (_ftpParser.ParsePEEvent(noticeLine) is IEnumerable<ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string>> ftpResult)
                            {
                                foreach (var result in ftpResult)
                                {
                                    results.Add(result);
                                }
                            }
                            break;
                        }
                    case "PortableExecutables::NonFtpPE":
                        {
                            if (_filesParser.ParsePEEvent(noticeLine) is IEnumerable<ValueTuple<IcsMitreTechnique, IcsMitreTactic, string, string, string>> filesResult)
                            {
                                foreach (var result in filesResult)
                                {
                                    results.Add(result);
                                }
                            }
                            break;
                        }
                    case "ARPSPOOF::Unsolicited_Reply":
                        {
                            var arpSpoofResult = ArpSpoofParser.ParseUnsolicitedReply(noticeLine);
                            results.Add(arpSpoofResult);
                            break;
                        }
                    default:
                        break;
                }
            }
            return results.Any() ? results : null;
        }
    }
}
