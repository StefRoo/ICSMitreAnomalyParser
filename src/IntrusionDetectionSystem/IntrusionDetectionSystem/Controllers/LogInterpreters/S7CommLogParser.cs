using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IntrusionDetectionSystem.Controllers
{
    public class S7CommLogParser : ILogParser
    {
        public bool CanProcess(string filePath)
        {
            return filePath.EndsWith("s7comm.log");
        }

        public IEnumerable<DataLine> ParseDataLines(IEnumerable<string> json)
        {
            var dataLines = new List<DataLine>();
            var serializer = new DataContractJsonSerializer(typeof(S7CommDataLine));

            foreach (var line in json)
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(line)))
                {
                    if (serializer.ReadObject(ms) is S7CommDataLine parsedLine)
                    {
                        dataLines.Add(parsedLine);
                    }
                }
            }

            return dataLines.Any() ? dataLines : null;
        }
    }
}