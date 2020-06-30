using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace IntrusionDetectionSystem.Controllers
{
    public class ModbusParser
    {
        public IEnumerable<(IcsMitreTechnique, IcsMitreTactic, string, string, string)> ParseModbusEvent(KeyValuePair<NoticeDataLine, IEnumerable<DataLine>> noticeLine)
        {
            if (!noticeLine.Value.Any())
            {
                return null;
            }

            var modbusLines = noticeLine.Value.Where(line => line is ModbusDataLine);
            if (!modbusLines.Any())
            {
                return null;
            }

            var modbusLine = modbusLines.FirstOrDefault() as ModbusDataLine;

            var results = new List<(IcsMitreTechnique, IcsMitreTactic, string, string, string)>();

            // Constants taken from https://docs.zeek.org/en/current/scripts/base/protocols/modbus/consts.zeek.html
            // Matches the Modbus function to its corresponding ICS MITRE techniques
            switch (modbusLine.Function)
            {
                case "READ_DISCRETE_INPUTS":
                case "READ_COILS":
                case "READ_INPUT_REGISTERS":
                case "READ_HOLDING_REGISTERS":
                case "READ_FIFO_QUEUE":
                case "READ_FILE_RECORD":
                    {
                        if (decimal.TryParse(modbusLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var modbusReadResult))
                        {
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, TimeConverter.UnixTimeToString(modbusReadResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeReadResult))
                        {
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, TimeConverter.UnixTimeToString(noticeReadResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, string.Empty, modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        break;
                    }                    
                case "WRITE_SINGLE_COIL":
                case "WRITE_MULTIPLE_COILS":
                case "WRITE_SINGLE_REGISTER":
                case "WRITE_MULTIPLE_REGISTERS":
                case "MASK_WRITE_REGISTER":
                case "WRITE_FILE_RECORD":
                    {
                        if (decimal.TryParse(modbusLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var modbusWriteResult))
                        {
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(modbusWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, TimeConverter.UnixTimeToString(modbusWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeWriteResult))
                        {
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, TimeConverter.UnixTimeToString(noticeWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, string.Empty, modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, string.Empty, modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        break;
                    }
                case "READ_WRITE_MULTIPLE_REGISTERS":
                    {
                        if (decimal.TryParse(modbusLine.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var modbusReadWriteResult))
                        {
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, TimeConverter.UnixTimeToString(modbusReadWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(modbusReadWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, TimeConverter.UnixTimeToString(modbusReadWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        else if (decimal.TryParse(noticeLine.Key.TimeStamp, NumberStyles.Any, CultureInfo.InvariantCulture, out var noticeReadWriteResult))
                        {
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, TimeConverter.UnixTimeToString(noticeReadWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, TimeConverter.UnixTimeToString(noticeReadWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, TimeConverter.UnixTimeToString(noticeReadWriteResult), modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        else
                        {
                            results.Add((IcsMitreTechnique.PointAndTagIdentification, IcsMitreTactic.Collection, string.Empty, modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ExecutionChangeProgramState, IcsMitreTactic.Execution, string.Empty, modbusLine.OriginAddress, modbusLine.ResponderAddress));
                            results.Add((IcsMitreTechnique.ImpairProcessControlChangeProgramState, IcsMitreTactic.ImpairProcessControl, string.Empty, modbusLine.OriginAddress, modbusLine.ResponderAddress));
                        }
                        break;
                    }                    
                default:
                    break;
            }

            return results.Any() ? results : null;
        }
    }
}