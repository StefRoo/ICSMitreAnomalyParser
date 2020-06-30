using IntrusionDetectionSystem.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IntrusionDetectionSystem.Controllers
{
    public class NoticeLogParser : ILogParser
    {
        public bool CanProcess(string filePath)
        {
            return filePath.EndsWith("notice.log");
        }

        public IEnumerable<DataLine> ParseDataLines(IEnumerable<string> json)
        {
            var dataLines = new List<DataLine>();
            var serializer = new DataContractJsonSerializer(typeof(NoticeDataLine));

            foreach (var line in json)
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(line)))
                {
                    if (serializer.ReadObject(ms) is NoticeDataLine parsedLine)
                    {
                        dataLines.Add(parsedLine);
                    }
                }
            }

            return dataLines.Any() ? dataLines : null;
        }

    }
}
