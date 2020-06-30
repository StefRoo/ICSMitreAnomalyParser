using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using IntrusionDetectionSystem.Models;

namespace IntrusionDetectionSystem.Controllers
{
    public class ProfinetLogParser : ILogParser
    {
        public bool CanProcess(string filePath)
        {
            return filePath.EndsWith("profinet.log");
        }

        public IEnumerable<DataLine> ParseDataLines(IEnumerable<string> json)
        {
            var dataLines = new List<DataLine>();
            var serializer = new DataContractJsonSerializer(typeof(ProfinetDataLine));

            foreach (var line in json)
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(line)))
                {
                    if (serializer.ReadObject(ms) is ProfinetDataLine parsedLine)
                    {
                        dataLines.Add(parsedLine);
                    }
                }
            }

            return dataLines.Any() ? dataLines : null;
        }
    }
}