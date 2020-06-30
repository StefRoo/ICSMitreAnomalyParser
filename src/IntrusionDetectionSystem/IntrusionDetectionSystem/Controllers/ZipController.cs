using IntrusionDetectionSystem.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;

namespace IntrusionDetectionSystem.Controllers
{
    public class ZipController : Controller
    {
        private readonly IEnumerable<ILogParser> _logParsers;
        private readonly NoticeParser _noticeParser;

        public ZipController(IEnumerable<ILogParser> logParsers, NoticeParser noticeParser)
        {
            _logParsers = logParsers;
            _noticeParser = noticeParser;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [RequestSizeLimit(1074790400)]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            var size = file?.Length;
            if (size <= 0)
            {
                return UnprocessableEntity(new ArgumentException(string.Format("File {0} is too short", file.FileName)));
            }

            // Saves the uploaded ZIP file to the wwwroot\images directory
            var zipName = Path.GetFileName(file.FileName);
            var filePath = Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot\images", zipName);

            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(fileStream);
            }

            // Extracts the ZIP file to a directory
            ZipFile.ExtractToDirectory(filePath, Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot\images"));

            // Cleans up the ZIP file to save space
            try
            {
                if (System.IO.File.Exists(filePath))
                {
                    System.IO.File.Delete(filePath);
                }
            }
            catch (Exception ex)
            {
                return Conflict(ex);
            }

            var dataLines = new List<DataLine>();

            // Loops through each file in the unzipped directory
            var dirPath = Directory.GetDirectories(Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot\images"));
            foreach (var fileName in Directory.GetFiles(dirPath.FirstOrDefault()))
            {
                var lines = new List<string>();

                using (var fileReader = new StreamReader(fileName))
                {
                    var jsonLines = new List<string>();
                    string line;

                    while ((line = fileReader.ReadLine()) != null)
                    {
                        jsonLines.Add(line);
                    }

                    // Parses the log file from json to our DataLine structure
                    if (ParseLogFile(fileName, jsonLines) is List<DataLine> parsedLines)
                    {
                        dataLines.AddRange(parsedLines);
                    }
                }

                // Cleans up the file to save space
                try
                {
                    if (System.IO.File.Exists(fileName))
                    {
                        System.IO.File.Delete(fileName);
                    }
                }
                catch (Exception ex)
                {
                    return Conflict(ex);
                }
            }

            // Cleans up the directory to save space
            try
            {
                if (Directory.Exists(dirPath.FirstOrDefault()))
                {
                    Directory.Delete(dirPath.FirstOrDefault());
                }
            }
            catch (Exception ex)
            {
                return Conflict(ex);
            }

            // Splits the parsed datalines into notice.log lines and the other log lines
            var lookUp = dataLines.ToLookup(line => line is NoticeDataLine);
            var noticeLines = lookUp[true];
            var otherLines = lookUp[false];

            // Removes the double lists to save memory
            dataLines = null;
            lookUp = null;

            // Matches the NoticeDataLines to the other DataLine objects with the same UID and timestamp,
            // also selects all the FilesDataLine objects for HTTP MicroBrowser parsing
            var noticeDictionary = MatchDataLines(noticeLines, otherLines);
            var filesDataLines = otherLines.Where(line => line is FilesDataLine);

            // Parses the NoticeDataLines to the ICS MITRE techniques
            var results = _noticeParser.ParseNotices(noticeDictionary, filesDataLines);
            if (results != null)
            {
                var readableResults = new List<(string, string, string, string, string)>();
                foreach (var result in results)
                {
                    (string IcsTechnique, string IcsTactic, string TimeStamp, string SourceIP, string DestIP) readableResult = new ValueTuple<string, string, string, string, string>(
                        result.Item1.ToString(), result.Item2.ToString(), result.Item3, result.Item4, result.Item5);
                    readableResults.Add(readableResult);
                }

                // Removes double results and sort on the timestamp
                var distinctResults = readableResults.Distinct().ToList();
                distinctResults.Sort((x, y) => x.Item3.CompareTo(y.Item3));

                var strResponse = string.Join("\n", distinctResults);
                return Ok(strResponse);
            }

            return Ok(new { count = (results != null) ? results.Count() : 0, size });
        }

        private IDictionary<NoticeDataLine, IEnumerable<DataLine>> MatchDataLines(IEnumerable<DataLine> noticeLines, IEnumerable<DataLine> otherLines)
        {
            var dictionary = new Dictionary<NoticeDataLine, IEnumerable<DataLine>>();

            foreach (NoticeDataLine noticeLine in noticeLines)
            {
                var matchingLines = otherLines.Where(line =>
                    string.Equals(line.TimeStamp, noticeLine.TimeStamp) &&
                    string.Equals(line.Uid, noticeLine.Uid));

                if (!matchingLines.Any())
                {
                    // If no matches can be found using both timestamp and UID, 
                    // only the UID will be used for matching. This is necessary for some
                    // Zeek notices that log later than their corresponding log streams
                    var inaccurateMatchingLines = otherLines.Where(line =>
                        string.Equals(line.Uid, noticeLine.Uid));
                    if (inaccurateMatchingLines.Any())
                    {
                        dictionary.Add(noticeLine, inaccurateMatchingLines);
                    }
                }
                else
                {
                    dictionary.Add(noticeLine, matchingLines);
                }
            }

            return dictionary.Any() ? dictionary : null;
        }

        private IEnumerable<DataLine> ParseLogFile(string fileName, List<string> json)
        {
            // Loops through the parsers, selecting the one that can parse the specified log file
            var parser = _logParsers.FirstOrDefault(x => x.CanProcess(fileName));
            if (parser == null)
            {
                // TODO: implement logging
                return null;
            }
            return parser.ParseDataLines(json) is IEnumerable<DataLine> dataLines ? dataLines : null;
        }
    }
}