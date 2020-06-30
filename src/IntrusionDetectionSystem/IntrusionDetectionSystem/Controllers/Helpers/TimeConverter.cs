using System;

namespace IntrusionDetectionSystem.Controllers
{
    public static class TimeConverter
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static string UnixTimeToString(decimal unixTime)
        {
            // Zeek outputs its timestamps in decimal point seconds; the smallest amount of time that can be
            // added to a DateTime in C# is a millisecond, so it needs to be multiplied by 1000 to get milliseconds.
            var rounded = (long)Math.Round(unixTime * 1000);
            return DateTimeToString(Epoch.AddMilliseconds(rounded));
        }

        private static string DateTimeToString(DateTime dateTime)
        {
            // Adjusts the formatting of the DateTime to include milliseconds.
            var milliSecond = dateTime.ToString("dd/MM/yyyy hh:mm:ss.fff tt");
            return milliSecond;
        }

        public static DateTime UnixTimeToDateTime(decimal unixTime)
        {
            // Zeek outputs its timestamps in decimal point seconds; the smallest amount of time that can be
            // added to a DateTime in C# is a millisecond, so it needs to be multiplied by 1000 to get milliseconds.
            var rounded = (long)Math.Round(unixTime * 1000);
            return Epoch.AddMilliseconds(rounded);
        }
    }
}