using IntrusionDetectionSystem.Models;
using System.Collections.Generic;

namespace IntrusionDetectionSystem.Controllers
{
    public interface ILogParser
    {
        bool CanProcess(string filePath);

        IEnumerable<DataLine> ParseDataLines(IEnumerable<string> json);
    }
}
