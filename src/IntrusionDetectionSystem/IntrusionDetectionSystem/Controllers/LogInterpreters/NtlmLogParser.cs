using IntrusionDetectionSystem.Models;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IntrusionDetectionSystem.Controllers
{
    public class NtlmLogParser : ILogParser
    {
        public bool CanProcess(string filePath)
        {
            return filePath.EndsWith("ntlm.log");
        }

        public IEnumerable<DataLine> ParseDataLines(IEnumerable<string> json)
        {
            var dataLines = new List<DataLine>();
            var serializer = new DataContractJsonSerializer(typeof(NtlmDataLine));

            foreach (var line in json)
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(line)))
                {
                    if (serializer.ReadObject(ms) is NtlmDataLine parsedLine)
                    {
                        dataLines.Add(parsedLine);
                    }
                }
            }

            return dataLines.Any() ? dataLines : null;
        }
    }
}